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
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ListenableFuture;
import org.opensearch.common.util.concurrent.OpenSearchExecutors;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.action.AlertingActions;
import org.opensearch.commons.alerting.action.PublishFindingsRequest;
import org.opensearch.commons.alerting.action.SubscribeFindingsResponse;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.InputStreamStreamInput;
import org.opensearch.core.common.io.stream.OutputStreamStreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.correlation.CorrelationRulesCache;
import org.opensearch.securityanalytics.correlation.DetectorLookupCache;
import org.opensearch.securityanalytics.correlation.JoinEngine;
import org.opensearch.securityanalytics.correlation.LogTypeListCache;
import org.opensearch.securityanalytics.correlation.VectorEmbeddingsEngine;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.correlation.alert.notifications.NotificationService;
import org.opensearch.securityanalytics.enrichment.WazuhEnrichedFindingService;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

public class TransportCorrelateFindingAction
        extends HandledTransportAction<ActionRequest, SubscribeFindingsResponse>
        implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportCorrelateFindingAction.class);

    private final DetectorIndices detectorIndices;

    private final CorrelationIndices correlationIndices;

    private final LogTypeService logTypeService;

    private final ClusterService clusterService;

    private final Settings settings;

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    private volatile TimeValue indexTimeout;

    private volatile long corrTimeWindow;

    private volatile long setupTimestamp;

    private volatile boolean enableAutoCorrelation;

    private final CorrelationAlertService correlationAlertService;

    private final NotificationService notificationService;

    private final WazuhEnrichedFindingService enrichedFindingService;

    private final DetectorLookupCache detectorLookupCache;

    private final LogTypeListCache logTypeListCache;

    private final CorrelationRulesCache correlationRulesCache;

    /**
     * Limits the number of correlation pipelines (one per published finding) running concurrently.
     * When alerting's doc-level monitor fan-out publishes many findings at once, this semaphore caps
     * peak demand on the search thread pool to avoid {@code OpenSearchRejectedExecutionException}
     * from the search thread pool's bounded queue.
     */
    private final Semaphore correlationPermits;

    /** Pipelines waiting for an in-flight permit; drained as permits are released. */
    private final ConcurrentLinkedQueue<AsyncCorrelateFindingAction> pendingStarts =
            new ConcurrentLinkedQueue<>();

    /**
     * Size of {@link #pendingStarts}. Incremented when an action is queued, decremented when one is
     * drained.
     */
    private final AtomicInteger pendingCount = new AtomicInteger();

    /**
     * Maximum allowed correlation backlog. When {@link #pendingCount} reaches this, new findings skip
     * correlation instead of growing the queue {@code
     * plugins.security_analytics.correlation.max_pending_findings}. They are still enriched.
     */
    private volatile int maxPendingFindings;

    /**
     * Count of findings that skipped correlation due to a full correlation backlog (for an occasional
     * WARN log).
     */
    private final AtomicLong skippedCorrelations = new AtomicLong();

    /**
     * Detector lookups against the detectors index currently running, by monitor id. A detector run
     * publishes all its findings at once, so with a cold {@link #detectorLookupCache} every finding
     * of the run would send the same search; instead the first one searches and the others wait for
     * its answer.
     */
    private final ConcurrentHashMap<String, ListenableFuture<Optional<Detector>>> detectorLookups =
            new ConcurrentHashMap<>();

    /** Tracks the current configured permit count to compute deltas on dynamic updates. */
    private volatile int currentMaxInFlight;

    // When the correlation backlog fills, write-block the events indices so no new events are
    // ingested. When it falls back to the low watermark, the block is lifted.

    /** Whether the events-index backpressure mechanism is active. */
    private volatile boolean eventsBackpressureEnabled;

    /** Block the events indices when the backlog reaches this %% of {@link #maxPendingFindings}. */
    private volatile int eventsHighWatermarkPercent;

    /** Lift the block when the backlog falls to this %% of {@link #maxPendingFindings}. */
    private volatile int eventsLowWatermarkPercent;

    /**
     * Index/data-stream pattern of the events indices to write-block. Fixed by design — the events
     * data stream is always {@code wazuh-events-v5-*}; making it configurable risks blocking the
     * wrong indices (or none), so it is intentionally not a setting.
     */
    private static final String EVENTS_INDEX_PATTERN = IndexUtils.WCS_EVENTS_INDEX_PATTERN;

    /** Current applied state of the events write block (true = blocked). */
    private final AtomicBoolean eventsBlocked = new AtomicBoolean(false);

    /** Guards against firing overlapping block/unblock cluster updates. */
    private final AtomicBoolean blockTransitionInFlight = new AtomicBoolean(false);

    static Map<String, CustomLogType> buildLogTypesFromHits(
            SearchHit[] hits, String monitorId, String findingId) {
        Map<String, CustomLogType> logTypes = new HashMap<>();
        for (SearchHit hit : hits) {
            addLogTypeIfValid(logTypes, hit.getSourceAsMap(), hit.getId(), monitorId, findingId);
        }
        return logTypes;
    }

    static void addLogTypeIfValid(
            Map<String, CustomLogType> logTypes,
            Map<String, Object> sourceMap,
            String hitId,
            String monitorId,
            String findingId) {
        Object nameObj = sourceMap.get("name");
        if (nameObj == null) {
            log.warn(
                    "Skipping malformed log type doc [{}] for monitor [{}] finding [{}]: missing field [name]. Available keys: {}",
                    hitId,
                    monitorId,
                    findingId,
                    sourceMap.keySet());
            return;
        }

        String name = nameObj.toString();
        try {
            logTypes.put(name, new CustomLogType(sourceMap));
        } catch (Exception e) {
            log.warn(
                    "Skipping malformed log type doc [{}] with name [{}] for monitor [{}] finding [{}]",
                    hitId,
                    name,
                    monitorId,
                    findingId,
                    e);
        }
    }

    @Inject
    public TransportCorrelateFindingAction(
            TransportService transportService,
            Client client,
            NamedXContentRegistry xContentRegistry,
            DetectorIndices detectorIndices,
            CorrelationIndices correlationIndices,
            LogTypeService logTypeService,
            ClusterService clusterService,
            Settings settings,
            ActionFilters actionFilters,
            CorrelationAlertService correlationAlertService,
            NotificationService notificationService,
            WazuhEnrichedFindingService enrichedFindingService,
            DetectorLookupCache detectorLookupCache,
            LogTypeListCache logTypeListCache,
            CorrelationRulesCache correlationRulesCache) {
        super(
                AlertingActions.SUBSCRIBE_FINDINGS_ACTION_NAME,
                transportService,
                actionFilters,
                PublishFindingsRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.detectorIndices = detectorIndices;
        this.correlationIndices = correlationIndices;
        this.logTypeService = logTypeService;
        this.clusterService = clusterService;
        this.settings = settings;
        this.correlationAlertService = correlationAlertService;
        this.notificationService = notificationService;
        this.enrichedFindingService = enrichedFindingService;
        this.detectorLookupCache = detectorLookupCache;
        this.logTypeListCache = logTypeListCache;
        this.correlationRulesCache = correlationRulesCache;
        this.currentMaxInFlight =
                SecurityAnalyticsSettings.CORRELATION_MAX_IN_FLIGHT_FINDINGS.get(settings);
        this.maxPendingFindings =
                SecurityAnalyticsSettings.CORRELATION_MAX_PENDING_FINDINGS.get(settings);
        this.correlationPermits = new AdjustableSemaphore(this.currentMaxInFlight);
        this.threadPool = this.detectorIndices.getThreadPool();

        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
        this.corrTimeWindow =
                SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW.get(this.settings).getMillis();
        this.enableAutoCorrelation =
                SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS.get(this.settings);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.INDEX_TIMEOUT, it -> indexTimeout = it);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW,
                        it -> corrTimeWindow = it.getMillis());
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS, it -> enableAutoCorrelation = it);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.ENRICHED_FINDINGS_ENABLED,
                        enrichedFindingService::setEnabled);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.CORRELATION_DETECTOR_CACHE_TTL, detectorLookupCache::setTtl);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.CORRELATION_MAX_IN_FLIGHT_FINDINGS, this::adjustMaxInFlight);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.CORRELATION_MAX_PENDING_FINDINGS,
                        newMax -> this.maxPendingFindings = newMax);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.CORRELATION_METADATA_CACHE_TTL,
                        ttl -> {
                            logTypeListCache.setTtl(ttl);
                            correlationRulesCache.setTtl(ttl);
                        });
        this.eventsBackpressureEnabled =
                SecurityAnalyticsSettings.EVENTS_BACKPRESSURE_ENABLED.get(this.settings);
        this.eventsHighWatermarkPercent =
                SecurityAnalyticsSettings.EVENTS_BACKPRESSURE_HIGH_WATERMARK_PERCENT.get(this.settings);
        this.eventsLowWatermarkPercent =
                SecurityAnalyticsSettings.EVENTS_BACKPRESSURE_LOW_WATERMARK_PERCENT.get(this.settings);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.EVENTS_BACKPRESSURE_ENABLED,
                        it -> this.eventsBackpressureEnabled = it);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.EVENTS_BACKPRESSURE_HIGH_WATERMARK_PERCENT,
                        it -> this.eventsHighWatermarkPercent = it);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.EVENTS_BACKPRESSURE_LOW_WATERMARK_PERCENT,
                        it -> this.eventsLowWatermarkPercent = it);
        this.setupTimestamp = System.currentTimeMillis();
    }

    /**
     * Adds {@code action} to the in-flight queue and starts as many queued pipelines as permits
     * allow. The terminal callbacks ({@link AsyncCorrelateFindingAction#onOperation()}, {@link
     * AsyncCorrelateFindingAction#onFailures(Exception)}) release the permit. When the backlog is
     * full, the finding skips correlation instead; it was already dispatched to enrichment by {@link
     * AsyncCorrelateFindingAction#start()}.
     */
    private void scheduleCorrelation(AsyncCorrelateFindingAction action) {
        // Check and reserve in one atomic step, so concurrent callers cannot all see room and push
        // the backlog past the limit.
        int max = maxPendingFindings;
        if (pendingCount.getAndUpdate(pending -> pending < max ? pending + 1 : pending) >= max) {
            long n = skippedCorrelations.incrementAndGet();
            if (n == 1 || n % 10000 == 0) {
                log.warn(
                        "Correlation queue capacity reached ({} pending). Skipping correlation for the current finding, which is still enriched. Total correlations skipped so far: {}",
                        max,
                        n);
            }
            action.skipCorrelationForBackpressure();
            return;
        }
        pendingStarts.add(action);
        evaluateBackpressure();
        drainPending();
    }

    private void drainPending() {
        while (correlationPermits.tryAcquire()) {
            AsyncCorrelateFindingAction next = pendingStarts.poll();
            if (next == null) {
                correlationPermits.release();
                return;
            }
            pendingCount.decrementAndGet();
            next.markPermitAcquired();
            next.doStart();
        }
        evaluateBackpressure();
    }

    private void releasePermitAndDrain() {
        correlationPermits.release();
        drainPending();
    }

    /**
     * Applies ingestion backpressure based on the current correlation backlog: at/above the high
     * watermark, write-block the events indices; at/below the low watermark, lift the block.
     */
    private void evaluateBackpressure() {
        if (!eventsBackpressureEnabled) {
            // If it got disabled while a block is applied, make sure we release it.
            if (eventsBlocked.get()) {
                setEventsWriteBlock(false);
            }
            return;
        }
        int max = maxPendingFindings;
        int pending = pendingCount.get();
        long high = (long) max * eventsHighWatermarkPercent / 100L;
        long low = (long) max * eventsLowWatermarkPercent / 100L;

        if (!eventsBlocked.get() && pending >= high) {
            setEventsWriteBlock(true);
        } else if (eventsBlocked.get() && pending <= low) {
            setEventsWriteBlock(false);
        }
    }

    /**
     * Fires a single async cluster-settings update to set or clear {@code index.blocks.write} on the
     * events indices. At most one transition is in flight at a time; {@link #eventsBlocked} flips
     * only after the update is acknowledged, so a failed update is retried on the next backlog
     * change.
     */
    private void setEventsWriteBlock(boolean block) {
        if (!blockTransitionInFlight.compareAndSet(false, true)) {
            return; // a transition is already in flight
        }
        UpdateSettingsRequest request =
                new UpdateSettingsRequest(EVENTS_INDEX_PATTERN)
                        .settings(Settings.builder().put("index.blocks.write", block).build())
                        .indicesOptions(IndicesOptions.lenientExpandOpen());
        log.warn(
                "Events ingestion backpressure: {} write block on '{}' (correlation backlog {}/{})",
                block ? "Applying" : "Lifting",
                EVENTS_INDEX_PATTERN,
                pendingCount.get(),
                maxPendingFindings);
        client
                .admin()
                .indices()
                .updateSettings(
                        request,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(AcknowledgedResponse response) {
                                eventsBlocked.set(block);
                                blockTransitionInFlight.set(false);
                                evaluateBackpressure();
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error(
                                        "Failed to {} events write block on '{}'",
                                        block ? "Apply" : "Lift",
                                        EVENTS_INDEX_PATTERN);
                                blockTransitionInFlight.set(false);
                            }
                        });
    }

    private synchronized void adjustMaxInFlight(int newMax) {
        int delta = newMax - currentMaxInFlight;
        if (delta > 0) {
            correlationPermits.release(delta);
        } else if (delta < 0) {
            ((AdjustableSemaphore) correlationPermits).reducePermits(-delta);
        }
        currentMaxInFlight = newMax;
    }

    /**
     * Resolves the detector that owns {@code monitorId}: from {@link #detectorLookupCache} when it
     * holds a fresh entry, otherwise from the detectors index, through a single search shared by
     * every finding of that monitor that asks while it runs. Answers {@link Optional#empty()} when no
     * detector owns the monitor.
     */
    private void resolveDetector(String monitorId, ActionListener<Optional<Detector>> listener) {
        Optional<Detector> cached = detectorLookupCache.get(monitorId);
        if (cached.isPresent()) {
            listener.onResponse(cached);
            return;
        }
        ListenableFuture<Optional<Detector>> lookup = new ListenableFuture<>();
        ListenableFuture<Optional<Detector>> running = detectorLookups.putIfAbsent(monitorId, lookup);
        if (running != null) {
            running.addListener(listener, OpenSearchExecutors.newDirectExecutorService());
            return;
        }
        lookup.addListener(listener, OpenSearchExecutors.newDirectExecutorService());
        // Unregister before answering, so a finding arriving after the answer starts a new lookup
        // instead of joining one that is over.
        searchDetector(
                monitorId,
                ActionListener.runBefore(lookup, () -> detectorLookups.remove(monitorId, lookup)));
    }

    /**
     * Searches the detectors index for the detector that owns {@code monitorId} and caches it. Every
     * outcome reaches {@code listener}, including a synchronous failure to send the search: an
     * unanswered lookup would leave every later finding of the monitor waiting on it.
     */
    private void searchDetector(String monitorId, ActionListener<Optional<Detector>> listener) {
        NestedQueryBuilder queryBuilder =
                QueryBuilders.nestedQuery(
                        "detector", QueryBuilders.matchQuery("detector.monitor_id", monitorId), ScoreMode.None);

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(queryBuilder);
        searchSourceBuilder.fetchSource(true);
        searchSourceBuilder.size(1);
        SearchRequest searchRequest = new SearchRequest();
        searchRequest.indices(Detector.DETECTORS_INDEX);
        searchRequest.source(searchSourceBuilder);
        searchRequest.preference(Preference.PRIMARY_FIRST.type());
        searchRequest.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30L));

        try {
            client.search(
                    searchRequest,
                    ActionListener.wrap(
                            response -> {
                                if (response.isTimedOut()) {
                                    listener.onFailure(
                                            new OpenSearchStatusException(
                                                    "Search request timed out", RestStatus.REQUEST_TIMEOUT));
                                    return;
                                }
                                SearchHits hits = response.getHits();
                                if (hits.getHits().length == 0) {
                                    listener.onResponse(Optional.empty());
                                    return;
                                }
                                Detector detector;
                                try {
                                    SearchHit hit = hits.getAt(0);
                                    XContentParser xcp =
                                            XContentType.JSON
                                                    .xContent()
                                                    .createParser(
                                                            xContentRegistry,
                                                            LoggingDeprecationHandler.INSTANCE,
                                                            hit.getSourceAsString());
                                    detector = Detector.docParse(xcp, hit.getId(), hit.getVersion());
                                } catch (Exception e) {
                                    log.error("Exception for request {}", searchRequest, e);
                                    listener.onFailure(e);
                                    return;
                                }
                                detectorLookupCache.put(monitorId, detector);
                                listener.onResponse(Optional.of(detector));
                            },
                            listener::onFailure));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    /** Exposes {@link Semaphore#reducePermits(int)} so the dynamic setting can shrink the cap. */
    private static final class AdjustableSemaphore extends Semaphore {
        AdjustableSemaphore(int permits) {
            super(permits);
        }

        @Override
        public void reducePermits(int reduction) {
            super.reducePermits(reduction);
        }
    }

    @Override
    protected void doExecute(
            Task task, ActionRequest request, ActionListener<SubscribeFindingsResponse> actionListener) {
        try {
            PublishFindingsRequest transformedRequest = transformRequest(request);

            // Enrichment is dispatched later, by AsyncCorrelateFindingAction.start(), only after
            // the finding's monitor is confirmed to belong to a SAP threat detector. This prevents
            // non-detector monitors (e.g. user-created doc-level monitors that watch
            // wazuh-findings-v5*, or Active Response monitors) from re-entering the enrichment
            // pipeline and producing an infinite loop.

            AsyncCorrelateFindingAction correlateFindingAction =
                    new AsyncCorrelateFindingAction(
                            task, transformedRequest, readUserFromThreadContext(this.threadPool), actionListener);

            if (!this.correlationIndices.correlationIndexExists()) {
                try {
                    this.correlationIndices.initCorrelationIndex(
                            ActionListener.wrap(
                                    response -> {
                                        if (response.isAcknowledged()) {
                                            IndexUtils.correlationIndexUpdated();
                                            if (IndexUtils.correlationIndexUpdated) {
                                                IndexUtils.lastUpdatedCorrelationHistoryIndex =
                                                        IndexUtils.getIndexNameWithAlias(
                                                                clusterService.state(),
                                                                CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX);
                                            }

                                            if (!correlationIndices.correlationMetadataIndexExists()) {
                                                try {
                                                    correlationIndices.initCorrelationMetadataIndex(
                                                            ActionListener.wrap(
                                                                    createIndexResponse -> {
                                                                        if (createIndexResponse.isAcknowledged()) {
                                                                            IndexUtils.correlationMetadataIndexUpdated();

                                                                            correlationIndices.setupCorrelationIndex(
                                                                                    indexTimeout,
                                                                                    setupTimestamp,
                                                                                    ActionListener.wrap(
                                                                                            bulkResponse -> {
                                                                                                if (bulkResponse.hasFailures()) {
                                                                                                    correlateFindingAction.skipCorrelation(
                                                                                                            "failed to seed correlation metadata index",
                                                                                                            new OpenSearchStatusException(
                                                                                                                    createIndexResponse.toString(),
                                                                                                                    RestStatus.INTERNAL_SERVER_ERROR));
                                                                                                } else {
                                                                                                    correlateFindingAction.start();
                                                                                                }
                                                                                            },
                                                                                            e ->
                                                                                                    correlateFindingAction.skipCorrelation(
                                                                                                            "failed to seed correlation metadata index",
                                                                                                            e)));
                                                                        } else {
                                                                            correlateFindingAction.skipCorrelation(
                                                                                    "correlation metadata index creation was not acknowledged",
                                                                                    new OpenSearchStatusException(
                                                                                            "Failed to create correlation metadata Index",
                                                                                            RestStatus.INTERNAL_SERVER_ERROR));
                                                                        }
                                                                    },
                                                                    e -> {
                                                                        if (ExceptionsHelper.unwrapCause(e)
                                                                                instanceof ResourceAlreadyExistsException) {
                                                                            correlateFindingAction.start();
                                                                        } else {
                                                                            correlateFindingAction.skipCorrelation(
                                                                                    "failed to create correlation metadata index", e);
                                                                        }
                                                                    }));
                                                } catch (Exception ex) {
                                                    correlateFindingAction.skipCorrelation(
                                                            "failed to create correlation metadata index", ex);
                                                }
                                            } else {
                                                correlateFindingAction.start();
                                            }
                                            if (!correlationIndices.correlationAlertIndexExists()) {
                                                try {
                                                    correlationIndices.initCorrelationAlertIndex(
                                                            ActionListener.wrap(
                                                                    createIndexResponse -> {
                                                                        if (createIndexResponse.isAcknowledged()) {
                                                                            IndexUtils.correlationAlertIndexUpdated();
                                                                        } else {
                                                                            correlateFindingAction.skipCorrelation(
                                                                                    "correlation alert index creation was not acknowledged",
                                                                                    new OpenSearchStatusException(
                                                                                            "Failed to create correlation alert Index",
                                                                                            RestStatus.INTERNAL_SERVER_ERROR));
                                                                        }
                                                                    },
                                                                    e -> {
                                                                        if (ExceptionsHelper.unwrapCause(e)
                                                                                instanceof ResourceAlreadyExistsException) {
                                                                            IndexUtils.correlationAlertIndexUpdated();
                                                                        } else {
                                                                            correlateFindingAction.skipCorrelation(
                                                                                    "failed to create correlation alert index", e);
                                                                        }
                                                                    }));
                                                } catch (Exception ex) {
                                                    correlateFindingAction.skipCorrelation(
                                                            "failed to create correlation alert index", ex);
                                                }
                                            }
                                        } else {
                                            correlateFindingAction.skipCorrelation(
                                                    "correlation index creation was not acknowledged",
                                                    new OpenSearchStatusException(
                                                            "Failed to create correlation Index",
                                                            RestStatus.INTERNAL_SERVER_ERROR));
                                        }
                                    },
                                    e -> {
                                        if (ExceptionsHelper.unwrapCause(e) instanceof ResourceAlreadyExistsException) {
                                            correlateFindingAction.start();
                                        } else {
                                            correlateFindingAction.skipCorrelation(
                                                    "failed to create correlation index", e);
                                        }
                                    }));
                } catch (Exception ex) {
                    correlateFindingAction.skipCorrelation("failed to create correlation index", ex);
                }
            } else {
                correlateFindingAction.start();
            }
        } catch (Exception e) {
            // Route synchronous failures to the listener instead of rethrowing. The caller
            // is the alerting plugin's publishFinding loop, and a synchronous throw there
            // unwinds the forEach and silently drops every subsequent finding in the batch.
            log.error("Unknown exception occurred while handling publish-findings request", e);
            actionListener.onFailure(
                    new SecurityAnalyticsException(
                            "Unknown exception occurred", RestStatus.INTERNAL_SERVER_ERROR, e));
        }
    }

    public class AsyncCorrelateFindingAction {
        private final PublishFindingsRequest request;
        private final JoinEngine joinEngine;
        private final VectorEmbeddingsEngine vectorEmbeddingsEngine;

        private final ActionListener<SubscribeFindingsResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        /**
         * Set to {@code true} when this pipeline has acquired an in-flight permit; gates the permit
         * release in {@link #onOperation()} / {@link #onFailures(Exception)} so early failures (before
         * {@link #start()} ever runs) do not over-release.
         */
        private volatile boolean permitAcquired = false;

        /**
         * Set when correlation bootstrap failed before {@link #doStart()} ever ran. The pipeline still
         * resolves the detector and dispatches enrichment in {@link #start()}, but it stops before
         * handing the finding to {@link JoinEngine}. See {@link #skipCorrelation}.
         */
        private volatile boolean correlationSkipped = false;

        /**
         * Set by the first {@link #start()}. Bootstrap can call {@link #skipCorrelation} for a pipeline
         * that already started (the alert index is created alongside the metadata check), and starting
         * it again would enrich the finding twice and queue it twice, leaking the correlation slot of
         * the second run.
         */
        private final AtomicBoolean started = new AtomicBoolean();

        /** The detector that owns the finding's monitor, resolved by {@link #start()}. */
        private volatile Detector detector;

        AsyncCorrelateFindingAction(
                Task task,
                PublishFindingsRequest request,
                User user,
                ActionListener<SubscribeFindingsResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;
            this.response = new AtomicReference<>();
            this.joinEngine =
                    new JoinEngine(
                            client,
                            request,
                            xContentRegistry,
                            corrTimeWindow,
                            indexTimeout,
                            this,
                            logTypeService,
                            enableAutoCorrelation,
                            correlationAlertService,
                            notificationService,
                            user,
                            correlationRulesCache);
            this.vectorEmbeddingsEngine =
                    new VectorEmbeddingsEngine(client, indexTimeout, corrTimeWindow, this);
        }

        /**
         * Public entry point. Resolves the detector that owns the finding's monitor and dispatches
         * enrichment, then hands the pipeline to the outer transport action, which queues it until an
         * in-flight permit is available; once acquired, {@link #doStart()} runs.
         *
         * <p>Enrichment is what writes the finding to {@code wazuh-findings-v5-*}, so it is dispatched
         * before the finding competes for a correlation slot: a full correlation backlog or a
         * correlation bootstrap failure skips the correlation of a finding, never the finding itself.
         * Findings of a monitor that no detector owns complete here, without taking a slot.
         */
        void start() {
            if (!started.compareAndSet(false, true)) {
                return;
            }
            // The detector lookup reads a system index. Like doStart(), it runs without the caller's
            // user.
            TransportCorrelateFindingAction.this.threadPool.getThreadContext().stashContext();
            if (!detectorIndices.detectorIndexExists()) {
                onFailures(
                        new SecurityAnalyticsException(
                                String.format(
                                        Locale.getDefault(),
                                        "Detector index %s doesnt exist",
                                        Detector.DETECTORS_INDEX),
                                RestStatus.INTERNAL_SERVER_ERROR,
                                new RuntimeException()));
                return;
            }
            resolveDetector(
                    request.getMonitorId(), ActionListener.wrap(this::onDetectorResolved, this::onFailures));
        }

        private void onDetectorResolved(Optional<Detector> resolved) {
            if (resolved.isEmpty()) {
                // Finding's monitor is not owned by a SAP threat detector (e.g. user-created
                // doc-level monitor, Active Response monitor). Correlation and enrichment are
                // SAP-only concerns, so this is a legitimate no-op rather than an error: complete the
                // request successfully.
                log.debug(
                        "No detector found for monitor id {}; skipping correlation and enrichment",
                        request.getMonitorId());
                onOperation();
                return;
            }
            this.detector = resolved.get();
            dispatchEnrichment(request.getFinding());
            if (correlationSkipped) {
                onOperation();
                return;
            }
            scheduleCorrelation(this);
        }

        void markPermitAcquired() {
            this.permitAcquired = true;
        }

        /**
         * Fires enrichment for a finding whose monitor has just been confirmed to belong to a SAP
         * threat detector. Failures are swallowed and logged so a misbehaving enrichment cannot block
         * correlation.
         */
        private void dispatchEnrichment(Finding finding) {
            try {
                enrichedFindingService.enrich(finding);
            } catch (Exception e) {
                log.warn("Enrichment dispatch failed for finding {}", finding.getId(), e);
            }
        }

        /**
         * Correlates the finding against the detector resolved by {@link #start()}; only invoked once a
         * permit has been acquired.
         */
        void doStart() {
            TransportCorrelateFindingAction.this.threadPool.getThreadContext().stashContext();
            if (correlationSkipped) {
                // Correlation bootstrap failed while this pipeline waited for a slot. The finding was
                // already enriched; complete and release the slot.
                onOperation();
                return;
            }
            try {
                joinEngine.onSearchDetectorResponse(detector, request.getFinding());
            } catch (Exception e) {
                onFailures(e);
            }
        }

        public void initCorrelationIndex(
                String detectorType,
                Map<String, List<String>> correlatedFindings,
                List<String> correlationRules) {
            try {
                if (!IndexUtils.correlationIndexUpdated) {
                    IndexUtils.updateIndexMapping(
                            CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX,
                            CorrelationIndices.correlationMappings(),
                            clusterService.state(),
                            client.admin().indices(),
                            ActionListener.wrap(
                                    response -> {
                                        if (response.isAcknowledged()) {
                                            IndexUtils.correlationIndexUpdated();
                                            getTimestampFeature(detectorType, correlatedFindings, null, correlationRules);
                                        } else {
                                            skipCorrelation(
                                                    "correlation index mapping update was not acknowledged",
                                                    new OpenSearchStatusException(
                                                            "Failed to create correlation Index",
                                                            RestStatus.INTERNAL_SERVER_ERROR));
                                        }
                                    },
                                    e -> skipCorrelation("failed to update correlation index mapping", e)),
                            true);
                } else {
                    getTimestampFeature(detectorType, correlatedFindings, null, correlationRules);
                }
            } catch (Exception ex) {
                skipCorrelation("failed to update correlation index mapping", ex);
            }
        }

        public void getTimestampFeature(
                String detectorType,
                Map<String, List<String>> correlatedFindings,
                Finding orphanFinding,
                List<String> correlationRules) {
            try {
                if (!correlationIndices.correlationMetadataIndexExists()) {
                    correlationIndices.initCorrelationMetadataIndex(
                            ActionListener.wrap(
                                    response -> {
                                        if (response.isAcknowledged()) {
                                            IndexUtils.correlationMetadataIndexUpdated();

                                            correlationIndices.setupCorrelationIndex(
                                                    indexTimeout,
                                                    setupTimestamp,
                                                    ActionListener.wrap(
                                                            bulkResponse -> {
                                                                if (bulkResponse.hasFailures()) {
                                                                    // Same bootstrap seeding as in doExecute(): without a
                                                                    // score document there is nothing for the search
                                                                    // below to find, so stop here instead of falling
                                                                    // through into it.
                                                                    skipCorrelation(
                                                                            "failed to seed correlation metadata index",
                                                                            new OpenSearchStatusException(
                                                                                    bulkResponse.toString(),
                                                                                    RestStatus.INTERNAL_SERVER_ERROR));
                                                                    return;
                                                                }

                                                                long findingTimestamp =
                                                                        request.getFinding().getTimestamp().toEpochMilli();
                                                                SearchRequest searchMetadataIndexRequest =
                                                                        getSearchMetadataIndexRequest();

                                                                client.search(
                                                                        searchMetadataIndexRequest,
                                                                        ActionListener.wrap(
                                                                                searchMetadataResponse -> {
                                                                                    if (searchMetadataResponse.getHits().getHits().length
                                                                                            == 0) {
                                                                                        // The score document was just seeded, so
                                                                                        // this means the write is not searchable
                                                                                        // yet. Reading hits[0] below would throw,
                                                                                        // so stop and let the next finding retry.
                                                                                        skipCorrelation(
                                                                                                "correlation metadata index has no score document yet",
                                                                                                new ResourceNotFoundException(
                                                                                                        "Failed to find hits in metadata index for finding id {}",
                                                                                                        request.getFinding().getId()));
                                                                                        return;
                                                                                    }

                                                                                    String id =
                                                                                            searchMetadataResponse.getHits().getHits()[0].getId();
                                                                                    Map<String, Object> hitSource =
                                                                                            searchMetadataResponse
                                                                                                    .getHits()
                                                                                                    .getHits()[0]
                                                                                                    .getSourceAsMap();
                                                                                    long scoreTimestamp =
                                                                                            (long) hitSource.get("scoreTimestamp");

                                                                                    long newScoreTimestamp =
                                                                                            findingTimestamp
                                                                                                    - CorrelationIndices.FIXED_HISTORICAL_INTERVAL;
                                                                                    if (newScoreTimestamp > scoreTimestamp) {
                                                                                        try {
                                                                                            IndexRequest scoreIndexRequest =
                                                                                                    getCorrelationMetadataIndexRequest(
                                                                                                            id, newScoreTimestamp);
                                                                                            float fixedTimestampFeature =
                                                                                                    Long.valueOf(
                                                                                                                    CorrelationIndices
                                                                                                                                    .FIXED_HISTORICAL_INTERVAL
                                                                                                                            / 1000L)
                                                                                                            .floatValue();

                                                                                            client.index(
                                                                                                    scoreIndexRequest,
                                                                                                    ActionListener.wrap(
                                                                                                            indexResponse ->
                                                                                                                    insertFindings(
                                                                                                                            fixedTimestampFeature,
                                                                                                                            correlatedFindings,
                                                                                                                            detectorType,
                                                                                                                            correlationRules,
                                                                                                                            orphanFinding),
                                                                                                            this::onFailures));
                                                                                        } catch (Exception ex) {
                                                                                            onFailures(ex);
                                                                                        }
                                                                                    } else {
                                                                                        float timestampFeature =
                                                                                                Long.valueOf(
                                                                                                                (findingTimestamp - scoreTimestamp) / 1000L)
                                                                                                        .floatValue();

                                                                                        insertFindings(
                                                                                                timestampFeature,
                                                                                                correlatedFindings,
                                                                                                detectorType,
                                                                                                correlationRules,
                                                                                                orphanFinding);
                                                                                    }
                                                                                },
                                                                                e ->
                                                                                        skipCorrelation(
                                                                                                "failed to read correlation metadata index", e)));
                                                            },
                                                            e ->
                                                                    skipCorrelation("failed to seed correlation metadata index", e)));
                                        } else {
                                            skipCorrelation(
                                                    "correlation metadata index creation was not acknowledged",
                                                    new OpenSearchStatusException(
                                                            "Failed to create correlation metadata Index",
                                                            RestStatus.INTERNAL_SERVER_ERROR));
                                        }
                                    },
                                    e -> {
                                        if (ExceptionsHelper.unwrapCause(e) instanceof ResourceAlreadyExistsException) {
                                            log.debug(
                                                    "Correlation metadata index already exists, proceeding with existing index");
                                            IndexUtils.correlationMetadataIndexUpdated();
                                            getTimestampFeature(
                                                    detectorType, correlatedFindings, orphanFinding, correlationRules);
                                        } else {
                                            skipCorrelation("failed to create correlation metadata index", e);
                                        }
                                    }));
                } else {
                    long findingTimestamp = this.request.getFinding().getTimestamp().toEpochMilli();
                    SearchRequest searchMetadataIndexRequest = getSearchMetadataIndexRequest();

                    client.search(
                            searchMetadataIndexRequest,
                            ActionListener.wrap(
                                    response -> {
                                        if (response.getHits().getHits().length == 0) {
                                            // The metadata index exists but its score document is not
                                            // searchable yet, e.g. it was seeded moments ago by another
                                            // finding. Transient, so skip instead of failing the run.
                                            skipCorrelation(
                                                    "correlation metadata index has no score document yet",
                                                    new ResourceNotFoundException(
                                                            "Failed to find hits in metadata index for finding id {}",
                                                            request.getFinding().getId()));
                                        } else {
                                            String id = response.getHits().getHits()[0].getId();
                                            Map<String, Object> hitSource =
                                                    response.getHits().getHits()[0].getSourceAsMap();
                                            long scoreTimestamp = (long) hitSource.get("scoreTimestamp");

                                            long newScoreTimestamp =
                                                    findingTimestamp - CorrelationIndices.FIXED_HISTORICAL_INTERVAL;
                                            if (newScoreTimestamp > scoreTimestamp) {
                                                IndexRequest scoreIndexRequest =
                                                        getCorrelationMetadataIndexRequest(id, newScoreTimestamp);
                                                float fixedTimestampFeature =
                                                        Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L)
                                                                .floatValue();

                                                client.index(
                                                        scoreIndexRequest,
                                                        ActionListener.wrap(
                                                                indexResponse ->
                                                                        insertFindings(
                                                                                fixedTimestampFeature,
                                                                                correlatedFindings,
                                                                                detectorType,
                                                                                correlationRules,
                                                                                orphanFinding),
                                                                this::onFailures));
                                            } else {
                                                float timestampFeature =
                                                        Long.valueOf((findingTimestamp - scoreTimestamp) / 1000L).floatValue();

                                                insertFindings(
                                                        timestampFeature,
                                                        correlatedFindings,
                                                        detectorType,
                                                        correlationRules,
                                                        orphanFinding);
                                            }
                                        }
                                    },
                                    e -> skipCorrelation("failed to read correlation metadata index", e)));
                }
            } catch (Exception ex) {
                skipCorrelation("failed to read correlation metadata index", ex);
            }
        }

        private SearchRequest getSearchLogTypeIndexRequest() {
            BoolQueryBuilder queryBuilder =
                    QueryBuilders.boolQuery().must(QueryBuilders.existsQuery("space"));
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(queryBuilder);
            searchSourceBuilder.fetchSource(true);
            searchSourceBuilder.size(10000);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(LogTypeService.LOG_TYPE_INDEX);
            searchRequest.source(searchSourceBuilder);
            searchRequest.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30L));
            return searchRequest;
        }

        private Map<String, CustomLogType> buildLogTypes(SearchHit[] hits) {
            return buildLogTypesFromHits(hits, request.getMonitorId(), request.getFinding().getId());
        }

        private IndexRequest getCorrelationMetadataIndexRequest(String id, long newScoreTimestamp)
                throws IOException {
            XContentBuilder scoreBuilder = XContentFactory.jsonBuilder().startObject();
            scoreBuilder.field("scoreTimestamp", newScoreTimestamp);
            scoreBuilder.field("root", false);
            scoreBuilder.endObject();

            return new IndexRequest(CorrelationIndices.CORRELATION_METADATA_INDEX)
                    .id(id)
                    .source(scoreBuilder)
                    .timeout(indexTimeout)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        }

        private void insertFindings(
                float timestampFeature,
                Map<String, List<String>> correlatedFindings,
                String detectorType,
                List<String> correlationRules,
                Finding orphanFinding) {
            withLogTypes(
                    logTypes -> {
                        if (correlatedFindings != null) {
                            if (correlatedFindings.isEmpty()) {
                                vectorEmbeddingsEngine.insertOrphanFindings(
                                        detectorType, request.getFinding(), timestampFeature, logTypes);
                            }
                            for (Map.Entry<String, List<String>> correlatedFinding :
                                    correlatedFindings.entrySet()) {
                                vectorEmbeddingsEngine.insertCorrelatedFindings(
                                        detectorType,
                                        request.getFinding(),
                                        correlatedFinding.getKey(),
                                        correlatedFinding.getValue(),
                                        timestampFeature,
                                        correlationRules,
                                        logTypes);
                            }
                        } else {
                            vectorEmbeddingsEngine.insertOrphanFindings(
                                    detectorType, orphanFinding, timestampFeature, logTypes);
                        }
                    });
        }

        /**
         * Calls {@code onLogTypes} with the cached log type list if a fresh entry is available,
         * otherwise issues the size-10000 search against {@link LogTypeService#LOG_TYPE_INDEX},
         * populates the cache, and then invokes the consumer.
         */
        private void withLogTypes(Consumer<Map<String, CustomLogType>> onLogTypes) {
            Optional<Map<String, CustomLogType>> cached = logTypeListCache.get();
            if (cached.isPresent()) {
                onLogTypes.accept(cached.get());
                return;
            }
            client.search(
                    getSearchLogTypeIndexRequest(),
                    ActionListener.wrap(
                            response -> {
                                if (response.isTimedOut()) {
                                    onFailures(
                                            new OpenSearchStatusException(
                                                    "Search request timed out", RestStatus.REQUEST_TIMEOUT));
                                    return;
                                }
                                Map<String, CustomLogType> logTypes = buildLogTypes(response.getHits().getHits());
                                logTypeListCache.put(logTypes);
                                onLogTypes.accept(logTypes);
                            },
                            this::onFailures));
        }

        private SearchRequest getSearchMetadataIndexRequest() {
            BoolQueryBuilder queryBuilder =
                    QueryBuilders.boolQuery().mustNot(QueryBuilders.termQuery("scoreTimestamp", 0L));
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(queryBuilder);
            searchSourceBuilder.fetchSource(true);
            searchSourceBuilder.size(1);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(CorrelationIndices.CORRELATION_METADATA_INDEX);
            searchRequest.source(searchSourceBuilder);
            searchRequest.preference(Preference.PRIMARY_FIRST.type());
            searchRequest.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30L));

            return searchRequest;
        }

        public void onOperation() {
            this.response.set(RestStatus.OK);
            if (counter.compareAndSet(false, true)) {
                if (permitAcquired) {
                    releasePermitAndDrain();
                }
                finishHim(null);
            }
        }

        /**
         * Completes this finding without correlation because the correlation backlog is full (H-11 load
         * shedding). {@link #start()} already dispatched the finding to enrichment, which writes it to
         * {@code wazuh-findings-v5-*}, so only correlation is skipped. No permit was acquired, so none
         * is released. Completed inline (no thread-pool hop) so shedding stays cheap under overload.
         */
        void skipCorrelationForBackpressure() {
            if (counter.compareAndSet(false, true)) {
                listener.onResponse(new SubscribeFindingsResponse(RestStatus.OK));
            }
        }

        /**
         * Skips correlation for this finding without failing the monitor execution, because bootstrap
         * of the correlation index/metadata/alert indices did not succeed for a reason other than
         * "already exists" (e.g. transient cluster-state contention right after a clean install, while
         * many other Security Analytics config indices are being created at the same time). The finding
         * is still enriched, which is what writes it to {@code wazuh-findings-v5-*}; only correlation
         * is skipped, and it is retried automatically on the next finding once the cluster settles and
         * the bootstrap succeeds. This is also reached from {@link #initCorrelationIndex} / {@link
         * #getTimestampFeature}, i.e. after {@link #start} already acquired a permit, so the permit
         * must be released here too when that happened — otherwise the in-flight semaphore leaks a
         * permit every time bootstrap fails on that later path.
         */
        void skipCorrelation(String reason, Exception cause) {
            log.warn(
                    "Skipping correlation for monitor id {} and finding id {}: {}",
                    request.getMonitorId(),
                    request.getFinding().getId(),
                    reason,
                    cause);
            if (!permitAcquired) {
                // start() enriches the finding and completes without queueing it. If it already ran
                // and the pipeline waits for a slot, doStart() completes it instead.
                correlationSkipped = true;
                start();
                return;
            }
            if (counter.compareAndSet(false, true)) {
                releasePermitAndDrain();
                listener.onResponse(new SubscribeFindingsResponse(RestStatus.OK));
            }
        }

        public void onFailures(Exception t) {
            log.error(
                    "Exception occurred while processing correlations for monitor id {} and finding id {}",
                    request.getMonitorId(),
                    request.getFinding().getId(),
                    t);
            if (counter.compareAndSet(false, true)) {
                if (permitAcquired) {
                    releasePermitAndDrain();
                }
                finishHim(t);
            }
        }

        private void finishHim(Exception t) {
            threadPool
                    .executor(ThreadPool.Names.GENERIC)
                    .execute(
                            ActionRunnable.supply(
                                    listener,
                                    () -> {
                                        if (t != null) {
                                            if (t instanceof OpenSearchStatusException) {
                                                throw t;
                                            }
                                            throw SecurityAnalyticsException.wrap(t);
                                        } else {
                                            return new SubscribeFindingsResponse(RestStatus.OK);
                                        }
                                    }));
        }
    }

    private PublishFindingsRequest transformRequest(ActionRequest request) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStreamStreamOutput osso = new OutputStreamStreamOutput(baos);
        request.writeTo(osso);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        InputStreamStreamInput issi = new InputStreamStreamInput(bais);
        return new PublishFindingsRequest(issi);
    }
}
