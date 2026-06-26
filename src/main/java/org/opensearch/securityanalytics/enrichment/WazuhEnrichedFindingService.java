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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

    /**
     * Maximum number of findings drained from the queue per in-flight permit. The batch's triggering
     * events are fetched in a single combined source-doc MultiGet instead of one MultiGet per
     * finding, eliminating ~{@code ENRICH_BATCH_SIZE}-1 of every {@code ENRICH_BATCH_SIZE}
     * round-trips to the event index under load.
     */
    private static final int ENRICH_BATCH_SIZE = 100;

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
     * Bounded LRU cache of rule metadata keyed by rule ID. Avoids repeated MultiGet RPCs for the same
     * rule across many findings, while capping heap growth: each value holds a full rule document
     * (including compliance and MITRE maps). Least-recently-used entries are evicted past {@code
     * ruleCacheMaxSize} and re-fetched on demand. Wrapped in a synchronized map because access-order
     * reordering mutates the structure on every read.
     */
    private final Map<String, Map<String, Object>> ruleMetadataCache;

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
            Client client,
            boolean enabled,
            TimeValue indexTimeout,
            ThreadPool threadPool,
            int ruleCacheMaxSize) {
        this.client = client;
        this.threadPool = threadPool;
        this.enabled = enabled;
        this.indexTimeout = indexTimeout;
        this.ruleMetadataCache =
                Collections.synchronizedMap(
                        new LinkedHashMap<>(16, 0.75f, true) {
                            @Override
                            protected boolean removeEldestEntry(Map.Entry<String, Map<String, Object>> eldest) {
                                return ruleCacheMaxSize > 0 && size() > ruleCacheMaxSize;
                            }
                        });
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
     * Drains the findings queue up to the number of available in-flight permits. Each acquired permit
     * covers a batch of up to {@link #ENRICH_BATCH_SIZE} findings whose triggering events are fetched
     * in one combined MultiGet; the permit is released once the whole batch completes.
     */
    private void processQueue() {
        while (this.inFlightPermits.tryAcquire()) {
            List<Finding> batch = new ArrayList<>(ENRICH_BATCH_SIZE);
            Finding finding;
            while (batch.size() < ENRICH_BATCH_SIZE && (finding = this.findingsQueue.poll()) != null) {
                batch.add(finding);
            }
            if (batch.isEmpty()) {
                this.inFlightPermits.release();
                break;
            }
            this.doEnrichBatch(batch);
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
     * Runs the async enrichment chain for a batch of findings. Fetches every triggering document
     * across the whole batch in one combined MultiGet (deduplicated by {@code index|docId}), then
     * hands each finding off to the rule-metadata step. The single in-flight permit acquired for this
     * batch is released exactly once — after the last finding completes, or immediately on a path
     * that starts no per-finding chains. Must reach {@link #enrichmentComplete()} (directly, or via
     * the per-finding {@code onComplete} callbacks) at every terminal point.
     */
    private void doEnrichBatch(List<Finding> batch) {
        // One combined MultiGet across the whole batch, deduplicated by index|docId so the same
        // event referenced by multiple findings is fetched only once.
        MultiGetRequest mget = new MultiGetRequest();
        Set<String> seenKeys = new HashSet<>();
        for (Finding finding : batch) {
            String index = finding.getIndex();
            for (String docId : finding.getRelatedDocIds()) {
                if (seenKeys.add(docKey(index, docId))) {
                    mget.add(new MultiGetRequest.Item(index, docId));
                }
            }
        }

        if (mget.getItems().isEmpty()) {
            this.enrichmentComplete();
            return;
        }

        try {
            this.client.multiGet(
                    mget,
                    ActionListener.wrap(
                            response -> {
                                // index|docId -> (source, category) shared across the batch.
                                Map<String, Map<String, Object>> keyToSource = new HashMap<>();
                                Map<String, String> keyToCategory = new HashMap<>();
                                for (MultiGetItemResponse item : response.getResponses()) {
                                    if (item.isFailed()
                                            || item.getResponse() == null
                                            || !item.getResponse().isExists()) {
                                        log.warn(
                                                "Triggering event {}/{} not found, skipping for affected findings",
                                                item.getIndex(),
                                                item.getId());
                                        continue;
                                    }
                                    Map<String, Object> eventSource = item.getResponse().getSourceAsMap();
                                    String category = WazuhEnrichedFindingService.resolveCategory(eventSource);
                                    if (category == null) {
                                        log.warn(
                                                "No valid wazuh.integration.category in event {}/{}, skipping",
                                                item.getIndex(),
                                                item.getId());
                                        continue;
                                    }
                                    String key = docKey(item.getIndex(), item.getId());
                                    keyToSource.put(key, eventSource);
                                    keyToCategory.put(key, category);
                                }

                                // Resolve each finding's valid docs from the shared lookup.
                                List<FindingDocs> validEntries = new ArrayList<>(batch.size());
                                for (Finding finding : batch) {
                                    String index = finding.getIndex();
                                    List<String> validDocIds = new ArrayList<>();
                                    List<Map<String, Object>> validSources = new ArrayList<>();
                                    List<String> validCategories = new ArrayList<>();
                                    for (String docId : finding.getRelatedDocIds()) {
                                        String key = docKey(index, docId);
                                        Map<String, Object> src = keyToSource.get(key);
                                        String cat = keyToCategory.get(key);
                                        if (src != null && cat != null) {
                                            validDocIds.add(docId);
                                            validSources.add(src);
                                            validCategories.add(cat);
                                        }
                                    }
                                    if (!validSources.isEmpty()) {
                                        validEntries.add(
                                                new FindingDocs(finding, validDocIds, validSources, validCategories));
                                    }
                                }

                                if (validEntries.isEmpty()) {
                                    this.enrichmentComplete();
                                    return;
                                }

                                // One permit covers the whole batch; release after the last finding completes.
                                AtomicInteger remaining = new AtomicInteger(validEntries.size());
                                Runnable onOneDone =
                                        () -> {
                                            if (remaining.decrementAndGet() == 0) {
                                                this.enrichmentComplete();
                                            }
                                        };

                                for (FindingDocs fd : validEntries) {
                                    this.fetchRuleMetadataAndIndex(
                                            fd.finding, fd.docIds, fd.eventSources, fd.categories, onOneDone);
                                }
                            },
                            e -> {
                                log.warn(
                                        "Batch source-doc MultiGet failed for {} findings, skipping enrichment",
                                        batch.size(),
                                        e);
                                this.enrichmentComplete();
                            }));
        } catch (Exception e) {
            // Synchronous failure (e.g. thread pool rejection) before the listener is wired in.
            // Release the single in-flight permit so it is not leaked.
            log.warn(
                    "Failed to submit batch source-doc MultiGet for {} findings, releasing in-flight slot",
                    batch.size(),
                    e);
            this.enrichmentComplete();
        }
    }

    /** Composite lookup key for a triggering document: {@code index|docId}. */
    private static String docKey(String index, String docId) {
        return index + '|' + docId;
    }

    /** Groups a finding with its resolved triggering documents from the combined batch MultiGet. */
    private static final class FindingDocs {
        final Finding finding;
        final List<String> docIds;
        final List<Map<String, Object>> eventSources;
        final List<String> categories;

        FindingDocs(
                Finding finding,
                List<String> docIds,
                List<Map<String, Object>> eventSources,
                List<String> categories) {
            this.finding = finding;
            this.docIds = docIds;
            this.eventSources = eventSources;
            this.categories = categories;
        }
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
            List<String> categories,
            Runnable onComplete) {

        List<DocLevelQuery> queries = finding.getDocLevelQueries();
        if (queries.isEmpty()) {
            this.buildAllFindingsAndComplete(
                    finding, docIds, eventSources, categories, List.of(), onComplete);
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
            this.buildAllFindingsAndComplete(
                    finding, docIds, eventSources, categories, queries, onComplete);
            return;
        }

        // Fetch all uncached rules in a single MultiGet (2 index lookups per rule)
        MultiGetRequest mget = new MultiGetRequest();
        for (String ruleId : uncachedRuleIds) {
            mget.add(new MultiGetRequest.Item(Rule.PRE_PACKAGED_RULES_INDEX, ruleId));
            mget.add(new MultiGetRequest.Item(Rule.CUSTOM_RULES_INDEX, ruleId));
        }

        try {
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
                                this.buildAllFindingsAndComplete(
                                        finding, docIds, eventSources, categories, queries, onComplete);
                            },
                            e -> {
                                log.warn(
                                        "Failed to fetch rule metadata for finding {}, indexing without rule fields",
                                        finding.getId(),
                                        e);
                                for (String ruleId : uncachedRuleIds) {
                                    this.ruleMetadataCache.putIfAbsent(ruleId, Map.of());
                                }
                                this.buildAllFindingsAndComplete(
                                        finding, docIds, eventSources, categories, queries, onComplete);
                            }));
        } catch (Exception e) {
            // Synchronous failure (e.g. thread pool rejection) before the listener is wired in.
            // Fall back to building without rule metadata so the in-flight permit is not leaked.
            log.warn(
                    "Failed to submit rule-metadata MultiGet for finding {}, indexing without rule fields",
                    finding.getId(),
                    e);
            for (String ruleId : uncachedRuleIds) {
                this.ruleMetadataCache.putIfAbsent(ruleId, Map.of());
            }
            this.buildAllFindingsAndComplete(
                    finding, docIds, eventSources, categories, queries, onComplete);
        }
    }

    /**
     * Generates and indexes M×N enriched findings (one per doc–rule combination), or M findings when
     * {@code queries} is empty (one per doc, without rule fields).
     *
     * <p>The synchronous build work (event-source copies and template interpolation) is offloaded to
     * the {@code GENERIC} thread pool so it does not run on the transport/listener thread that
     * completed the upstream MultiGet and would otherwise compete with request handling.
     *
     * <p>Wrapped in try/finally so {@link #enrichmentComplete()} always runs, even if a build throws
     * synchronously. Each doc is also guarded so a single bad event does not strand the in-flight
     * permit and stall {@link #findingsQueue} for the rest of the process's lifetime.
     */
    private void buildAllFindingsAndComplete(
            Finding finding,
            List<String> docIds,
            List<Map<String, Object>> eventSources,
            List<String> categories,
            List<DocLevelQuery> queries,
            Runnable onComplete) {
        try {
            this.threadPool
                    .executor(ThreadPool.Names.GENERIC)
                    .execute(
                            () -> {
                                try {
                                    for (int i = 0; i < docIds.size(); i++) {
                                        try {
                                            this.buildDocAndIndex(
                                                    finding, categories.get(i), eventSources.get(i), docIds.get(i), queries);
                                        } catch (Exception e) {
                                            log.warn(
                                                    "Failed to build enriched finding for finding {} doc {}",
                                                    finding.getId(),
                                                    docIds.get(i),
                                                    e);
                                        }
                                    }
                                } finally {
                                    onComplete.run();
                                }
                            });
        } catch (Exception e) {
            // Submission was rejected (e.g. thread pool queue full). Signal completion for this
            // finding here so the batch's in-flight permit is not leaked; otherwise enrichment
            // stalls once MAX_IN_FLIGHT is reached.
            log.warn(
                    "Failed to submit enrichment build for finding {}, releasing in-flight slot",
                    finding.getId(),
                    e);
            onComplete.run();
        }
    }

    // ── Step 3: assemble the enriched document ───────────────────────────────

    /**
     * Builds and indexes the enriched documents for a single triggering event. The per-doc base (full
     * event-source copy and the {@code event.*} object) is built once and reused across all N rules;
     * only the {@code wazuh.rule} object varies per rule. When {@code queries} is empty the base doc
     * is indexed once without rule fields.
     *
     * <p>Reusing the base map is safe because {@link #indexEnrichedFinding} serializes the document
     * to bytes synchronously, so the map can be mutated for the next rule afterwards.
     */
    @SuppressWarnings("unchecked")
    private void buildDocAndIndex(
            Finding finding,
            String category,
            Map<String, Object> eventSource,
            String docId,
            List<DocLevelQuery> queries) {

        // Per-doc base, built once and reused across all rules.
        Map<String, Object> doc = new HashMap<>(eventSource);

        // Top-level finding metadata — use the original event's timestamp
        doc.put("@timestamp", eventSource.get("@timestamp"));

        // event.* — merge existing event fields, then overlay doc_id and index
        Map<String, Object> eventObj = new HashMap<>();
        Object existingEvent = eventSource.get("event");
        if (existingEvent instanceof Map) {
            eventObj.putAll((Map<String, Object>) existingEvent);
        }
        eventObj.put("doc_id", docId);
        eventObj.put("index", finding.getIndex());
        doc.put("event", eventObj);

        if (queries.isEmpty()) {
            this.indexEnrichedFinding(category, doc);
            return;
        }

        Object existingWazuh = eventSource.get("wazuh");
        for (DocLevelQuery query : queries) {
            try {
                Map<String, Object> ruleMetadata =
                        this.ruleMetadataCache.getOrDefault(query.getId(), Map.of());

                // wazuh.rule — merge into a fresh copy of the existing wazuh map per rule.
                Map<String, Object> wazuhObj = new HashMap<>();
                if (existingWazuh instanceof Map) {
                    wazuhObj.putAll((Map<String, Object>) existingWazuh);
                }
                wazuhObj.put("rule", this.buildRuleObject(query, ruleMetadata, eventSource));
                doc.put("wazuh", wazuhObj);

                this.indexEnrichedFinding(category, doc);
            } catch (Exception e) {
                log.warn(
                        "Failed to build enriched finding for finding {} doc {} rule {}",
                        finding.getId(),
                        docId,
                        query.getId(),
                        e);
            }
        }
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
            Map<String, Object> interpolated =
                    TemplateInterpolator.interpolateNestedMitreMap((Map<String, ?>) mitre, eventSource);
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
            log.debug("Flushing {} pending enriched findings", bulk.numberOfActions());
            this.client.bulk(
                    bulk,
                    ActionListener.wrap(
                            response -> {
                                if (response.hasFailures()) {
                                    log.error(
                                            "Bulk indexing of enriched findings completed with failures: {}",
                                            response.buildFailureMessage());
                                } else {
                                    log.debug("Bulk indexing of enriched findings completed successfully");
                                }
                            },
                            e -> log.warn("Bulk indexing of enriched findings failed", e)));
        }
    }
}
