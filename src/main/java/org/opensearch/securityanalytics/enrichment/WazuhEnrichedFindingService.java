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
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.transport.client.Client;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Enriches Alerting findings with the full triggering event source and Sigma rule metadata, then
 * indexes the result into {@code wazuh-findings-v5-{logtype}-*}.
 *
 * <p>Enrichment is fire-and-forget: failures are logged at WARN level and never propagate to the
 * caller. The existing {@code .opensearch-sap-{logtype}-findings-*} write path is unaffected.
 */
public class WazuhEnrichedFindingService {

    private static final Logger log = LogManager.getLogger(WazuhEnrichedFindingService.class);

    private final Client client;
    private final TimeValue indexTimeout;
    private volatile boolean enabled;

    public WazuhEnrichedFindingService(Client client, boolean enabled, TimeValue indexTimeout) {
        this.client = client;
        this.enabled = enabled;
        this.indexTimeout = indexTimeout;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Entry point. Called from {@code TransportCorrelateFindingAction} after the detector is
     * resolved. All work is async; the caller is not blocked.
     */
    public void enrich(Finding finding, String logType) {
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
                        eventSource -> this.fetchRuleMetadataAndIndex(finding, logType, eventSource),
                        e -> {
                            log.warn(
                                    "Failed to fetch triggering event {}/{} for finding {}, indexing without event source",
                                    sourceIndex,
                                    docId,
                                    finding.getId(),
                                    e);
                            this.fetchRuleMetadataAndIndex(finding, logType, Map.of());
                        }));
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

    // ── Step 2: fetch rule metadata, then build and index ────────────────────

    private void fetchRuleMetadataAndIndex(
            Finding finding, String logType, Map<String, Object> eventSource) {
        List<DocLevelQuery> queries = finding.getDocLevelQueries();
        if (queries.isEmpty()) {
            this.buildAndIndex(finding, logType, eventSource, null, Map.of());
            return;
        }

        DocLevelQuery primaryQuery = queries.getFirst();
        String ruleId = primaryQuery.getId();

        MultiGetRequest mget = new MultiGetRequest();
        mget.add(new MultiGetRequest.Item(Rule.PRE_PACKAGED_RULES_INDEX, ruleId));
        mget.add(new MultiGetRequest.Item(Rule.CUSTOM_RULES_INDEX, ruleId));

        this.client.multiGet(
                mget,
                ActionListener.wrap(
                        response -> {
                            Map<String, Object> ruleMetadata = this.extractFirstHit(response);
                            this.buildAndIndex(finding, logType, eventSource, primaryQuery, ruleMetadata);
                        },
                        e -> {
                            log.warn(
                                    "Failed to fetch rule metadata for rule {}, indexing without rule fields",
                                    ruleId,
                                    e);
                            this.buildAndIndex(finding, logType, eventSource, primaryQuery, Map.of());
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
            String logType,
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

        this.indexEnrichedFinding(logType, doc);
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

    // ── Step 4: index to wazuh-findings-v5-{logtype}-* ───────────────────────

    private void indexEnrichedFinding(String logType, Map<String, Object> document) {
        String alias = DetectorMonitorConfig.getWazuhFindingsIndex(logType);

        IndexRequest request =
                new IndexRequest(alias).source(document, XContentType.JSON).timeout(this.indexTimeout);

        this.client.index(
                request,
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse response) {
                        log.debug("Indexed enriched finding to {}/{}", alias, response.getId());
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.warn("Failed to index enriched finding to {}", alias, e);
                    }
                });
    }
}
