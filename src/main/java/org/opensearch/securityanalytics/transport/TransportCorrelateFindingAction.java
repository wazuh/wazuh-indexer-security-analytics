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
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
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
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
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

    /** Tracks the current configured permit count to compute deltas on dynamic updates. */
    private volatile int currentMaxInFlight;

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
                        SecurityAnalyticsSettings.CORRELATION_METADATA_CACHE_TTL,
                        ttl -> {
                            logTypeListCache.setTtl(ttl);
                            correlationRulesCache.setTtl(ttl);
                        });
        this.setupTimestamp = System.currentTimeMillis();
    }

    /**
     * Adds {@code action} to the in-flight queue and starts as many queued pipelines as permits
     * allow. The terminal callbacks ({@link AsyncCorrelateFindingAction#onOperation()}, {@link
     * AsyncCorrelateFindingAction#onFailures(Exception)}) release the permit.
     */
    private void scheduleCorrelation(AsyncCorrelateFindingAction action) {
        pendingStarts.add(action);
        drainPending();
    }

    private void drainPending() {
        while (correlationPermits.tryAcquire()) {
            AsyncCorrelateFindingAction next = pendingStarts.poll();
            if (next == null) {
                correlationPermits.release();
                return;
            }
            next.markPermitAcquired();
            next.doStart();
        }
    }

    private void releasePermitAndDrain() {
        correlationPermits.release();
        drainPending();
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

            // Dispatch enrichment up front, completely outside the correlation throttle. The
            // throttle's pendingStarts queue and per-pipeline permit are exposed to permit
            // leaks if any async chain in JoinEngine/VectorEmbeddingsEngine fails to reach a
            // terminal callback (e.g. under search-pool rejection). Decoupling enrichment
            // here guarantees every published finding produces an enrichment dispatch.
            try {
                enrichedFindingService.enrich(transformedRequest.getFinding());
            } catch (Exception e) {
                log.warn(
                        "Enrichment dispatch failed for finding {}",
                        transformedRequest.getFinding().getId(),
                        e);
            }

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
                                                                                                    correlateFindingAction.onFailures(
                                                                                                            new OpenSearchStatusException(
                                                                                                                    createIndexResponse.toString(),
                                                                                                                    RestStatus.INTERNAL_SERVER_ERROR));
                                                                                                }

                                                                                                correlateFindingAction.start();
                                                                                            },
                                                                                            correlateFindingAction::onFailures));
                                                                        } else {
                                                                            correlateFindingAction.onFailures(
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
                                                                            correlateFindingAction.onFailures(e);
                                                                        }
                                                                    }));
                                                } catch (Exception ex) {
                                                    correlateFindingAction.onFailures(ex);
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
                                                                            correlateFindingAction.onFailures(
                                                                                    new OpenSearchStatusException(
                                                                                            "Failed to create correlation metadata Index",
                                                                                            RestStatus.INTERNAL_SERVER_ERROR));
                                                                        }
                                                                    },
                                                                    e -> {
                                                                        if (ExceptionsHelper.unwrapCause(e)
                                                                                instanceof ResourceAlreadyExistsException) {
                                                                            IndexUtils.correlationAlertIndexUpdated();
                                                                        } else {
                                                                            correlateFindingAction.onFailures(e);
                                                                        }
                                                                    }));
                                                } catch (Exception ex) {
                                                    correlateFindingAction.onFailures(ex);
                                                }
                                            }
                                        } else {
                                            correlateFindingAction.onFailures(
                                                    new OpenSearchStatusException(
                                                            "Failed to create correlation Index",
                                                            RestStatus.INTERNAL_SERVER_ERROR));
                                        }
                                    },
                                    e -> {
                                        if (ExceptionsHelper.unwrapCause(e) instanceof ResourceAlreadyExistsException) {
                                            correlateFindingAction.start();
                                        } else {
                                            correlateFindingAction.onFailures(e);
                                        }
                                    }));
                } catch (Exception ex) {
                    correlateFindingAction.onFailures(ex);
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
         * Public entry point. Hands the pipeline to the outer transport action, which queues it until
         * an in-flight permit is available; once acquired, {@link #doStart()} runs.
         */
        void start() {
            scheduleCorrelation(this);
        }

        void markPermitAcquired() {
            this.permitAcquired = true;
        }

        /** Body of {@code start()}; only invoked once a permit has been acquired. */
        void doStart() {
            TransportCorrelateFindingAction.this.threadPool.getThreadContext().stashContext();
            String monitorId = request.getMonitorId();
            Finding finding = request.getFinding();

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

            Optional<Detector> cached = detectorLookupCache.get(monitorId);
            if (cached.isPresent()) {
                try {
                    joinEngine.onSearchDetectorResponse(cached.get(), finding);
                } catch (Exception e) {
                    onFailures(e);
                }
                return;
            }

            NestedQueryBuilder queryBuilder =
                    QueryBuilders.nestedQuery(
                            "detector",
                            QueryBuilders.matchQuery("detector.monitor_id", monitorId),
                            ScoreMode.None);

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(queryBuilder);
            searchSourceBuilder.fetchSource(true);
            searchSourceBuilder.size(1);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(Detector.DETECTORS_INDEX);
            searchRequest.source(searchSourceBuilder);
            searchRequest.preference(Preference.PRIMARY_FIRST.type());
            searchRequest.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30L));

            client.search(
                    searchRequest,
                    ActionListener.wrap(
                            response -> {
                                if (response.isTimedOut()) {
                                    onFailures(
                                            new OpenSearchStatusException(
                                                    "Search request timed out", RestStatus.REQUEST_TIMEOUT));
                                }

                                SearchHits hits = response.getHits();
                                if (hits.getHits().length > 0) {
                                    try {
                                        SearchHit hit = hits.getAt(0);

                                        XContentParser xcp =
                                                XContentType.JSON
                                                        .xContent()
                                                        .createParser(
                                                                xContentRegistry,
                                                                LoggingDeprecationHandler.INSTANCE,
                                                                hit.getSourceAsString());
                                        Detector detector = Detector.docParse(xcp, hit.getId(), hit.getVersion());
                                        detectorLookupCache.put(monitorId, detector);
                                        joinEngine.onSearchDetectorResponse(detector, finding);
                                    } catch (Exception e) {
                                        log.error("Exception for request {}", searchRequest, e);
                                        onFailures(e);
                                    }
                                } else {
                                    onFailures(
                                            new OpenSearchStatusException(
                                                    "detector not found given monitor id " + request.getMonitorId(),
                                                    RestStatus.INTERNAL_SERVER_ERROR));
                                }
                            },
                            this::onFailures));
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
                                            onFailures(
                                                    new OpenSearchStatusException(
                                                            "Failed to create correlation Index",
                                                            RestStatus.INTERNAL_SERVER_ERROR));
                                        }
                                    },
                                    this::onFailures),
                            true);
                } else {
                    getTimestampFeature(detectorType, correlatedFindings, null, correlationRules);
                }
            } catch (Exception ex) {
                onFailures(ex);
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
                                                                    onFailures(
                                                                            new OpenSearchStatusException(
                                                                                    bulkResponse.toString(),
                                                                                    RestStatus.INTERNAL_SERVER_ERROR));
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
                                                                                        onFailures(
                                                                                                new ResourceNotFoundException(
                                                                                                        "Failed to find hits in metadata index for finding id {}",
                                                                                                        request.getFinding().getId()));
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
                                                                                this::onFailures));
                                                            },
                                                            this::onFailures));
                                        } else {
                                            Exception e =
                                                    new OpenSearchStatusException(
                                                            "Failed to create correlation metadata Index",
                                                            RestStatus.INTERNAL_SERVER_ERROR);
                                            onFailures(e);
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
                                            onFailures(e);
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
                                            onFailures(
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
                                    this::onFailures));
                }
            } catch (Exception ex) {
                onFailures(ex);
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
