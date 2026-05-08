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
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;
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
 *
 * <p>Concurrent in-flight enrichment chains are bounded by {@link #MAX_IN_FLIGHT} to prevent
 * transport-layer overload on resource-constrained nodes.
 */
public class WazuhEnrichedFindingService implements Closeable {

    private static final Logger log = LogManager.getLogger(WazuhEnrichedFindingService.class);

    /** Number of enriched findings accumulated before a bulk index request is fired. */
    private static final int BULK_BATCH_SIZE = 100;

    /** Maximum number of concurrent async enrichment chains (MultiGet + build + buffer). */
    private static final int MAX_IN_FLIGHT = 50;

    /** Interval at which leftover pending requests are flushed regardless of batch size. */
    private static final TimeValue FLUSH_INTERVAL = TimeValue.timeValueSeconds(5);

    /** Valid base categories derived from {@link LOG_CATEGORY}. */
    private static final Set<String> VALID_CATEGORIES =
            Arrays.stream(LOG_CATEGORY.values())
                    .map(LOG_CATEGORY::getLowerCaseName)
                    .collect(Collectors.toUnmodifiableSet());

    private final Client client;
    private final ThreadPool threadPool;
    private final TimeValue indexTimeout;
    private volatile boolean enabled;

    /**
     * Cache of rule metadata keyed by rule ID. Avoids repeated MultiGet RPCs for the same rule across
     * many findings produced by the same detector run.
     */
    private final ConcurrentHashMap<String, Map<String, Object>> ruleMetadataCache =
            new ConcurrentHashMap<>();

    /** Findings waiting to be enriched, processed when an in-flight slot becomes available. */
    private final ConcurrentLinkedQueue<Finding> findingsQueue = new ConcurrentLinkedQueue<>();

    /** Limits the number of concurrent async enrichment chains to avoid transport-layer overload. */
    private final Semaphore inFlightPermits = new Semaphore(MAX_IN_FLIGHT);

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
        this.threadPool = threadPool;
        this.enabled = enabled;
        this.indexTimeout = indexTimeout;
        this.flushSchedule =
                threadPool.scheduleWithFixedDelay(
                        this::periodicFlush, FLUSH_INTERVAL, ThreadPool.Names.GENERIC);
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

        this.findingsQueue.add(finding);
        this.processQueue();
    }

    /**
     * Drains the findings queue up to the number of available in-flight permits. Each finding starts
     * an async enrichment chain that releases its permit on completion.
     */
    private void processQueue() {
        while (this.inFlightPermits.tryAcquire()) {
            Finding finding = this.findingsQueue.poll();
            if (finding == null) {
                this.inFlightPermits.release();
                break;
            }
            this.doEnrich(finding);
        }
    }

    /**
     * Releases an in-flight permit and attempts to process more queued findings. Called at every
     * terminal point of the async enrichment chain (success or failure).
     */
    private void enrichmentComplete() {
        this.inFlightPermits.release();
        this.processQueue();
    }

    /**
     * Runs the async enrichment chain for a single finding. Fetches all M related documents in one
     * MultiGet, then hands off to the rule-metadata step. Must call {@link #enrichmentComplete()} at
     * every terminal point.
     */
    private void doEnrich(Finding finding) {
        String sourceIndex = finding.getIndex();
        List<String> relatedDocIds = finding.getRelatedDocIds();

        MultiGetRequest mget = new MultiGetRequest();
        for (String docId : relatedDocIds) {
            mget.add(new MultiGetRequest.Item(sourceIndex, docId));
        }

        this.client.multiGet(
                mget,
                ActionListener.wrap(
                        response -> {
                            List<String> validDocIds = new ArrayList<>();
                            List<Map<String, Object>> validEventSources = new ArrayList<>();
                            List<String> validCategories = new ArrayList<>();

                            for (MultiGetItemResponse item : response.getResponses()) {
                                if (item.isFailed() || !item.getResponse().isExists()) {
                                    log.warn(
                                            "Triggering event {}/{} not found for finding {}",
                                            sourceIndex,
                                            item.getId(),
                                            finding.getId());
                                    continue;
                                }
                                Map<String, Object> eventSource = item.getResponse().getSourceAsMap();
                                String category = WazuhEnrichedFindingService.resolveCategory(eventSource);
                                if (category == null) {
                                    log.warn(
                                            "No valid wazuh.integration.category in event {}/{} for finding {}, skipping",
                                            sourceIndex,
                                            item.getId(),
                                            finding.getId());
                                    continue;
                                }
                                validDocIds.add(item.getId());
                                validEventSources.add(eventSource);
                                validCategories.add(category);
                            }

                            if (validEventSources.isEmpty()) {
                                this.enrichmentComplete();
                                return;
                            }

                            this.fetchRuleMetadataAndIndex(
                                    finding, validDocIds, validEventSources, validCategories);
                        },
                        e -> {
                            log.warn(
                                    "Failed to fetch triggering events for finding {}, skipping enrichment",
                                    finding.getId(),
                                    e);
                            this.enrichmentComplete();
                        }));
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

    /**
     * Fetches rule metadata for every N {@link DocLevelQuery} in the finding (using the cache for
     * already-seen rules and a single batched MultiGet for the rest), then generates M×N enriched
     * findings via {@link #buildAllFindingsAndComplete}.
     */
    private void fetchRuleMetadataAndIndex(
            Finding finding,
            List<String> docIds,
            List<Map<String, Object>> eventSources,
            List<String> categories) {

        List<DocLevelQuery> queries = finding.getDocLevelQueries();
        if (queries.isEmpty()) {
            for (int i = 0; i < docIds.size(); i++) {
                this.buildAndIndex(
                        finding, categories.get(i), eventSources.get(i), docIds.get(i), null, Map.of());
            }
            this.enrichmentComplete();
            return;
        }

        // Collect rule IDs not yet in the cache
        List<String> uncachedRuleIds =
                queries.stream()
                        .map(DocLevelQuery::getId)
                        .filter(id -> !this.ruleMetadataCache.containsKey(id))
                        .distinct()
                        .collect(Collectors.toList());

        if (uncachedRuleIds.isEmpty()) {
            this.buildAllFindingsAndComplete(finding, docIds, eventSources, categories, queries);
            return;
        }

        // Fetch all uncached rules in a single MultiGet (2 index lookups per rule)
        MultiGetRequest mget = new MultiGetRequest();
        for (String ruleId : uncachedRuleIds) {
            mget.add(new MultiGetRequest.Item(Rule.PRE_PACKAGED_RULES_INDEX, ruleId));
            mget.add(new MultiGetRequest.Item(Rule.CUSTOM_RULES_INDEX, ruleId));
        }

        this.client.multiGet(
                mget,
                ActionListener.wrap(
                        response -> {
                            // Take the first valid hit per rule ID
                            Map<String, Map<String, Object>> fetched = new HashMap<>();
                            for (MultiGetItemResponse item : response.getResponses()) {
                                String ruleId = item.getId();
                                if (fetched.containsKey(ruleId)) continue;
                                if (!item.isFailed() && item.getResponse().isExists()) {
                                    fetched.put(ruleId, item.getResponse().getSourceAsMap());
                                }
                            }
                            for (String ruleId : uncachedRuleIds) {
                                this.ruleMetadataCache.put(ruleId, fetched.getOrDefault(ruleId, Map.of()));
                            }
                            this.buildAllFindingsAndComplete(finding, docIds, eventSources, categories, queries);
                        },
                        e -> {
                            log.warn(
                                    "Failed to fetch rule metadata for finding {}, indexing without rule fields",
                                    finding.getId(),
                                    e);
                            for (String ruleId : uncachedRuleIds) {
                                this.ruleMetadataCache.putIfAbsent(ruleId, Map.of());
                            }
                            this.buildAllFindingsAndComplete(finding, docIds, eventSources, categories, queries);
                        }));
    }

    /** Generates and indexes M×N enriched findings (one per doc–rule combination). */
    private void buildAllFindingsAndComplete(
            Finding finding,
            List<String> docIds,
            List<Map<String, Object>> eventSources,
            List<String> categories,
            List<DocLevelQuery> queries) {
        for (int i = 0; i < docIds.size(); i++) {
            for (DocLevelQuery query : queries) {
                Map<String, Object> ruleMetadata =
                        this.ruleMetadataCache.getOrDefault(query.getId(), Map.of());
                this.buildAndIndex(
                        finding, categories.get(i), eventSources.get(i), docIds.get(i), query, ruleMetadata);
            }
        }
        this.enrichmentComplete();
    }

    // ── Step 3: assemble the enriched document ───────────────────────────────

    @SuppressWarnings("unchecked")
    private void buildAndIndex(
            Finding finding,
            String category,
            Map<String, Object> eventSource,
            String docId,
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
        eventObj.put("doc_id", docId);
        eventObj.put("index", finding.getIndex());
        eventObj.put("ingested", eventSource.get("@timestamp"));
        doc.put("event", eventObj);

        // rule.*
        if (primaryQuery != null) {
            doc.put("rule", this.buildRuleObject(primaryQuery, ruleMetadata, eventSource));
        }

        this.indexEnrichedFinding(category, doc);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> buildRuleObject(
            DocLevelQuery query, Map<String, Object> ruleMetadata, Map<String, Object> eventSource) {
        Map<String, Object> rule = new HashMap<>();
        rule.put("id", query.getId());
        rule.put("sigma_id", query.getId());

        // Interpolate title and tags against the triggering event
        rule.put("title", TemplateInterpolator.interpolate(query.getName(), eventSource));
        rule.put("tags", TemplateInterpolator.interpolateList(query.getTags(), eventSource));

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

        // Interpolate compliance and mitre maps against the triggering event
        Object compliance = nested.get("compliance");
        if (compliance instanceof Map) {
            Map<String, List<String>> interpolated =
                    TemplateInterpolator.interpolateMapOfLists((Map<String, ?>) compliance, eventSource);
            if (interpolated != null && !interpolated.isEmpty()) {
                rule.put("compliance", interpolated);
            }
        }

        Object mitre = nested.get("mitre");
        if (mitre instanceof Map) {
            Map<String, List<String>> interpolated =
                    TemplateInterpolator.interpolateMapOfLists((Map<String, ?>) mitre, eventSource);
            if (interpolated != null && !interpolated.isEmpty()) {
                rule.put("mitre", interpolated);
            }
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
        log.debug("Added enriched finding to pending requests: {}", document);
        if (this.pendingCount.incrementAndGet() % BULK_BATCH_SIZE == 0) {
            this.drainAndFlush();
        }
    }

    /**
     * Called by the periodic schedule to flush leftover index requests and process queued findings.
     */
    private void periodicFlush() {
        this.drainAndFlush();
        this.processQueue();
    }

    /**
     * Drains all pending index requests from the queue and fires a single bulk request. Safe to call
     * concurrently: {@link ConcurrentLinkedQueue#poll()} guarantees each item is delivered to exactly
     * one caller.
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
        try (ThreadContext.StoredContext ignored = this.threadPool.getThreadContext().stashContext()) {
            log.info("Flushing {} pending enriched findings", bulk.numberOfActions());
            this.client.bulk(
                    bulk,
                    ActionListener.wrap(
                            response -> {
                                if (response.hasFailures()) {
                                    log.error(
                                            "Bulk indexing of enriched findings completed with failures: {}",
                                            response.buildFailureMessage());
                                } else {
                                    log.info("Bulk indexing of enriched findings completed successfully");
                                }
                            },
                            e -> log.warn("Bulk indexing of enriched findings failed", e)));
        }
    }
}
