/*
 * Copyright (C) 2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package org.opensearch.securityanalytics.enrichment;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.LOG_CATEGORY;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.io.Closeable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Enriches Alerting findings with the full triggering event source and Sigma rule metadata, then
 * indexes the result into {@code wazuh-findings-v5-{category}-*}.
 *
 * <p>Enrichment is fire-and-forget: failures are logged at WARN level and never propagate to the
 * caller. The existing {@code .opensearch-sap-{category}-findings-*} write path is unaffected.
 *
 * <p>Rule metadata is cached in memory to avoid repeated round-trips for the same rule across
 * findings. Index requests are batched into bulk requests every {@link #BULK_BATCH_SIZE} items,
 * with a periodic flush every {@link #FLUSH_INTERVAL} to drain any remainder.
 */
public class WazuhEnrichedFindingService implements Closeable {

    private static final Logger log = LogManager.getLogger(WazuhEnrichedFindingService.class);

    /** Number of enriched findings accumulated before a bulk index request is fired. */
    private static final int BULK_BATCH_SIZE = 100;

    /** Interval at which leftover pending requests are flushed regardless of batch size. */
    private static final TimeValue FLUSH_INTERVAL = TimeValue.timeValueSeconds(5);

    /** Valid base categories derived from {@link LOG_CATEGORY}. */
    private static final Set<String> VALID_CATEGORIES =
            Arrays.stream(LOG_CATEGORY.values())
                    .map(LOG_CATEGORY::getLowerCaseName)
                    .collect(Collectors.toUnmodifiableSet());

    private final Client client;
    private final TimeValue indexTimeout;
    private volatile boolean enabled;

    /**
     * Cache of rule metadata keyed by rule ID. Avoids repeated MultiGet RPCs for the same rule across
     * many findings produced by the same detector run.
     */
    private final ConcurrentHashMap<String, Map<String, Object>> ruleMetadataCache =
            new ConcurrentHashMap<>();

    /**
     * Buffer of pending index requests, flushed as a bulk request every {@link #BULK_BATCH_SIZE}
     * items.
     */
    private final ConcurrentLinkedQueue<IndexRequest> pendingRequests = new ConcurrentLinkedQueue<>();

    private final AtomicInteger pendingCount = new AtomicInteger(0);

    private final Scheduler.Cancellable flushSchedule;

    public WazuhEnrichedFindingService(
            Client client, boolean enabled, TimeValue indexTimeout, ThreadPool threadPool) {
        this.client = client;
        this.enabled = enabled;
        this.indexTimeout = indexTimeout;
        this.flushSchedule =
                threadPool.scheduleWithFixedDelay(
                        this::drainAndFlush, FLUSH_INTERVAL, ThreadPool.Names.GENERIC);
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public void close() {
        this.flushSchedule.cancel();
    }

    /**
     * Entry point. Called from {@code TransportCorrelateFindingAction} after the detector is
     * resolved. All work is async; the caller is not blocked.
     */
    public void enrich(Finding finding) {
        if (!this.enabled) {
            return;
        }

        List<String> relatedDocIds = finding.getRelatedDocIds();
        if (relatedDocIds.isEmpty()) {
            log.warn("Finding {} has no related_doc_ids, skipping enrichment", finding.getId());
            return;
        }

        String sourceIndex = finding.getIndex();
        String docId = relatedDocIds.getFirst();

        this.fetchTriggeringEvent(
                sourceIndex,
                docId,
                ActionListener.wrap(
                        eventSource -> {
                            String category = WazuhEnrichedFindingService.resolveCategory(eventSource);
                            if (category == null) {
                                log.warn(
                                        "No valid wazuh.integration.category in event {}/{} for finding {}, skipping enrichment",
                                        sourceIndex,
                                        docId,
                                        finding.getId());
                                return;
                            }
                            this.fetchRuleMetadataAndIndex(finding, category, eventSource);
                        },
                        e ->
                                log.warn(
                                        "Failed to fetch triggering event {}/{} for finding {}, skipping enrichment",
                                        sourceIndex,
                                        docId,
                                        finding.getId(),
                                        e)));
    }

    // ── Step 1: fetch triggering event ───────────────────────────────────────

    private void fetchTriggeringEvent(
            String index, String docId, ActionListener<Map<String, Object>> listener) {
        MultiGetRequest mget = new MultiGetRequest();
        mget.add(new MultiGetRequest.Item(index, docId));

        this.client.multiGet(
                mget,
                ActionListener.wrap(
                        response -> {
                            MultiGetItemResponse[] items = response.getResponses();
                            if (items.length > 0 && !items[0].isFailed() && items[0].getResponse().isExists()) {
                                listener.onResponse(items[0].getResponse().getSourceAsMap());
                            } else {
                                log.warn("Triggering event {}/{} not found or mget failed", index, docId);
                                listener.onResponse(Map.of());
                            }
                        },
                        listener::onFailure));
    }

    // ── Category resolution ─────────────────────────────────────────────────

    /**
     * Extracts the findings category from the triggering event's {@code wazuh.integration.category}
     * field. Returns {@code null} when the field is missing or contains an unrecognized value,
     * signaling that enrichment should be skipped for this event.
     */
    @SuppressWarnings("unchecked")
    private static String resolveCategory(Map<String, Object> eventSource) {
        Object wazuhObj = eventSource.get("wazuh");
        if (!(wazuhObj instanceof Map)) {
            return null;
        }
        Object integrationObj = ((Map<String, Object>) wazuhObj).get("integration");
        if (!(integrationObj instanceof Map)) {
            return null;
        }
        Object categoryObj = ((Map<String, Object>) integrationObj).get("category");
        if (categoryObj == null) {
            return null;
        }
        String category = categoryObj.toString();
        return VALID_CATEGORIES.contains(category) ? category : null;
    }

    // ── Step 2: fetch rule metadata (with cache), then build and index ────────

    private void fetchRuleMetadataAndIndex(
            Finding finding, String category, Map<String, Object> eventSource) {
        List<DocLevelQuery> queries = finding.getDocLevelQueries();
        if (queries.isEmpty()) {
            this.buildAndIndex(finding, category, eventSource, null, Map.of());
            return;
        }

        DocLevelQuery primaryQuery = queries.getFirst();
        String ruleId = primaryQuery.getId();

        Map<String, Object> cached = this.ruleMetadataCache.get(ruleId);
        if (cached != null) {
            this.buildAndIndex(finding, category, eventSource, primaryQuery, cached);
            return;
        }

        MultiGetRequest mget = new MultiGetRequest();
        mget.add(new MultiGetRequest.Item(Rule.PRE_PACKAGED_RULES_INDEX, ruleId));
        mget.add(new MultiGetRequest.Item(Rule.CUSTOM_RULES_INDEX, ruleId));

        this.client.multiGet(
                mget,
                ActionListener.wrap(
                        response -> {
                            Map<String, Object> ruleMetadata = this.extractFirstHit(response);
                            this.ruleMetadataCache.put(ruleId, ruleMetadata);
                            this.buildAndIndex(finding, category, eventSource, primaryQuery, ruleMetadata);
                        },
                        e -> {
                            log.warn(
                                    "Failed to fetch rule metadata for rule {}, indexing without rule fields",
                                    ruleId,
                                    e);
                            this.buildAndIndex(finding, category, eventSource, primaryQuery, Map.of());
                        }));
    }

    private Map<String, Object> extractFirstHit(MultiGetResponse response) {
        for (MultiGetItemResponse item : response.getResponses()) {
            if (!item.isFailed() && item.getResponse().isExists()) {
                return item.getResponse().getSourceAsMap();
            }
        }
        return Map.of();
    }

    // ── Step 3: assemble the enriched document ───────────────────────────────

    @SuppressWarnings("unchecked")
    private void buildAndIndex(
            Finding finding,
            String category,
            Map<String, Object> eventSource,
            DocLevelQuery primaryQuery,
            Map<String, Object> ruleMetadata) {

        Map<String, Object> doc = new HashMap<>(eventSource);

        // Top-level finding metadata
        doc.put("@timestamp", finding.getTimestamp());

        // event.* — merge existing event fields, then overlay doc_id and index
        Map<String, Object> eventObj = new HashMap<>();
        Object existingEvent = eventSource.get("event");
        if (existingEvent instanceof Map) {
            eventObj.putAll((Map<String, Object>) existingEvent);
        }
        eventObj.put("doc_id", finding.getRelatedDocIds().getFirst());
        eventObj.put("index", finding.getIndex());
        eventObj.put("ingested", eventSource.get("@timestamp"));
        doc.put("event", eventObj);

        // rule.*
        if (primaryQuery != null) {
            doc.put("rule", this.buildRuleObject(primaryQuery, ruleMetadata));
        }

        this.indexEnrichedFinding(category, doc);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> buildRuleObject(
            DocLevelQuery query, Map<String, Object> ruleMetadata) {
        Map<String, Object> rule = new HashMap<>();
        rule.put("id", query.getId());
        rule.put("title", query.getName());
        rule.put("tags", query.getTags());
        rule.put("sigma_id", query.getId());

        // The pre-packaged rules index stores each doc as {"rule": {...}}.
        Map<String, Object> nested = ruleMetadata;
        if (ruleMetadata.containsKey("rule") && ruleMetadata.get("rule") instanceof Map) {
            nested = (Map<String, Object>) ruleMetadata.get("rule");
        }

        Object level = nested.get("level");
        if (level != null) {
            rule.put("level", level.toString());
        }

        Object status = nested.get("status");
        if (status != null) {
            rule.put("status", status.toString());
        }

        Object compliance = nested.get("compliance");
        if (compliance != null) {
            rule.put("compliance", compliance);
        }

        Object mitre = nested.get("mitre");
        if (mitre != null) {
            rule.put("mitre", mitre);
        }

        return rule;
    }

    // ── Step 4: buffer and bulk-index to wazuh-findings-v5-{category}-* ──────

    private void indexEnrichedFinding(String category, Map<String, Object> document) {
        String alias = DetectorMonitorConfig.getWazuhFindingsIndex(category);
        IndexRequest request =
                new IndexRequest(alias)
                        .source(document, XContentType.JSON)
                        .opType(DocWriteRequest.OpType.CREATE)
                        .timeout(this.indexTimeout);

        this.pendingRequests.add(request);
        if (this.pendingCount.incrementAndGet() % BULK_BATCH_SIZE == 0) {
            this.drainAndFlush();
        }
    }

    /**
     * Drains all pending requests from the queue and fires a single bulk request. Safe to call
     * concurrently: {@link ConcurrentLinkedQueue#poll()} guarantees each item is delivered to exactly
     * one caller. Called by both the batch trigger and the periodic flush schedule.
     */
    private void drainAndFlush() {
        BulkRequest bulk = new BulkRequest().timeout(this.indexTimeout);
        IndexRequest req;
        while ((req = this.pendingRequests.poll()) != null) {
            bulk.add(req);
        }
        if (bulk.numberOfActions() == 0) {
            return;
        }
        this.client.bulk(
                bulk,
                ActionListener.wrap(
                        response -> {
                            for (BulkItemResponse item : response.getItems()) {
                                if (item.isFailed()) {
                                    log.warn(
                                            "Failed to bulk-index enriched finding {}: {}",
                                            item.getId(),
                                            item.getFailureMessage());
                                }
                            }
                        },
                        e -> log.warn("Bulk indexing of enriched findings failed", e)));
    }
}
