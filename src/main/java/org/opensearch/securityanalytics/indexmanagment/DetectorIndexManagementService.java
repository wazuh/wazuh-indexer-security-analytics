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
package org.opensearch.securityanalytics.indexmanagment;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.rollover.RolloverInfo;
import org.opensearch.action.admin.indices.rollover.RolloverRequest;
import org.opensearch.action.admin.indices.rollover.RolloverResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.*;

public class DetectorIndexManagementService extends AbstractLifecycleComponent
        implements ClusterStateListener {

    private Logger logger = LogManager.getLogger(DetectorIndexManagementService.class);

    private final Client client;
    private final ThreadPool threadPool;
    private final ClusterService clusterService;
    private final LogTypeService logTypeService;
    private Settings settings;

    private volatile Boolean alertHistoryEnabled;
    private volatile Boolean findingHistoryEnabled;

    private volatile Long alertHistoryMaxDocs;
    private volatile Long findingHistoryMaxDocs;

    private volatile Long correlationHistoryMaxDocs;

    private volatile TimeValue alertHistoryMaxAge;
    private volatile TimeValue findingHistoryMaxAge;

    private volatile TimeValue correlationHistoryMaxAge;

    private volatile TimeValue alertHistoryRolloverPeriod;
    private volatile TimeValue findingHistoryRolloverPeriod;

    private volatile TimeValue correlationHistoryRolloverPeriod;

    private volatile TimeValue alertHistoryRetentionPeriod;
    private volatile TimeValue findingHistoryRetentionPeriod;

    private volatile TimeValue correlationHistoryRetentionPeriod;

    /**
     * How long a detector's query index generation must have been out of use before it is deleted.
     * See {@link #selectUnusedQueryIndexGenerations}.
     */
    static final TimeValue QUERY_INDEX_GENERATION_GRACE_PERIOD = TimeValue.timeValueHours(1);

    /**
     * A generation of a detector's dedicated query index ({@link
     * DetectorMonitorConfig#getRuleIndexOptimized}), or of its chained-findings counterpart. The
     * random UUID makes the alias unique to one detector.
     */
    private static final Pattern DEDICATED_QUERY_INDEX_GENERATION =
            Pattern.compile(
                    "^\\.opensearch-sap-.+-detectors-queries-optimized-"
                            + "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                            + "(_chained_findings)?-\\d{6}$");

    /**
     * The history indices are found by name, not through the log types: the log type listing stops at
     * {@link LogTypeService#MAX_LOG_TYPE_COUNT} names, and a removed log type is not listed at all.
     * Each pattern ends with the date and counter of a rolled-over history index, so it cannot match
     * an active alerts index ({@code .opensearch-sap-<log type>-alerts}), which has no write alias
     * and would be deleted once old enough.
     */
    static final Pattern ALERT_HISTORY_INDEX =
            Pattern.compile("^\\.opensearch-sap-.+-alerts-history-\\d{4}\\.\\d{2}\\.\\d{2}-\\d+$");

    static final Pattern ALERT_HISTORY_WRITE_ALIAS =
            Pattern.compile("^\\.opensearch-sap-.+-alerts-history$");

    static final Pattern FINDING_HISTORY_INDEX =
            Pattern.compile("^\\.opensearch-sap-.+-findings-\\d{4}\\.\\d{2}\\.\\d{2}-\\d+$");

    static final Pattern FINDING_HISTORY_WRITE_ALIAS =
            Pattern.compile("^\\.opensearch-sap-.+-findings$");

    static final Pattern CORRELATION_HISTORY_INDEX =
            Pattern.compile("^\\.opensearch-sap-correlation-history-\\d{4}\\.\\d{2}\\.\\d{2}-\\d+$");

    static final Pattern CORRELATION_HISTORY_WRITE_ALIAS =
            Pattern.compile(
                    "^" + Pattern.quote(CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX) + "$");

    private volatile boolean isClusterManager = false;

    private Scheduler.Cancellable scheduledAlertsRollover = null;
    private Scheduler.Cancellable scheduledFindingsRollover = null;

    private Scheduler.Cancellable scheduledCorrelationHistoryRollover = null;

    // Replaced whole, never modified: the alert and finding sweeps both rebuild them, at the same
    // time when their periods match, while the other one and clusterChanged iterate them.
    private volatile List<HistoryIndexInfo> alertHistoryIndices = List.of();
    private volatile List<HistoryIndexInfo> findingHistoryIndices = List.of();

    HistoryIndexInfo correlationHistoryIndex = null;

    @Inject
    public DetectorIndexManagementService(
            Settings settings,
            Client client,
            ThreadPool threadPool,
            ClusterService clusterService,
            LogTypeService logTypeService) {
        this.settings = settings;
        this.client = client;
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.logTypeService = logTypeService;

        clusterService.addListener(this);

        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(ALERT_HISTORY_ENABLED, this::setAlertHistoryEnabled);
        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        ALERT_HISTORY_MAX_DOCS,
                        maxDocs -> {
                            setAlertHistoryMaxDocs(maxDocs);
                            for (HistoryIndexInfo h : alertHistoryIndices) {
                                h.maxDocs = maxDocs;
                            }
                        });
        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        ALERT_HISTORY_INDEX_MAX_AGE,
                        maxAge -> {
                            setAlertHistoryMaxAge(maxAge);
                            for (HistoryIndexInfo h : alertHistoryIndices) {
                                h.maxAge = maxAge;
                            }
                        });
        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        ALERT_HISTORY_ROLLOVER_PERIOD,
                        timeValue -> {
                            DetectorIndexManagementService.this.alertHistoryRolloverPeriod = timeValue;
                            rescheduleAlertRollover();
                        });
        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        ALERT_HISTORY_RETENTION_PERIOD, this::setAlertHistoryRetentionPeriod);

        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(FINDING_HISTORY_ENABLED, this::setFindingHistoryEnabled);
        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        FINDING_HISTORY_MAX_DOCS,
                        maxDocs -> {
                            setFindingHistoryMaxDocs(maxDocs);
                            for (HistoryIndexInfo h : findingHistoryIndices) {
                                h.maxDocs = maxDocs;
                            }
                        });
        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        FINDING_HISTORY_INDEX_MAX_AGE,
                        maxAge -> {
                            setFindingHistoryMaxAge(maxAge);
                            for (HistoryIndexInfo h : findingHistoryIndices) {
                                h.maxAge = maxAge;
                            }
                        });
        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        FINDING_HISTORY_ROLLOVER_PERIOD,
                        timeValue -> {
                            DetectorIndexManagementService.this.findingHistoryRolloverPeriod = timeValue;
                            rescheduleFindingRollover();
                        });
        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        FINDING_HISTORY_RETENTION_PERIOD, this::setFindingHistoryRetentionPeriod);

        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        CORRELATION_HISTORY_MAX_DOCS,
                        maxDocs -> {
                            setCorrelationHistoryMaxDocs(maxDocs);
                            if (correlationHistoryIndex != null) {
                                correlationHistoryIndex.maxDocs = maxDocs;
                            }
                        });

        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        CORRELATION_HISTORY_INDEX_MAX_AGE,
                        maxAge -> {
                            setCorrelationHistoryMaxAge(maxAge);
                            if (correlationHistoryIndex != null) {
                                correlationHistoryIndex.maxAge = maxAge;
                            }
                        });

        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        CORRELATION_HISTORY_ROLLOVER_PERIOD,
                        timeValue -> {
                            DetectorIndexManagementService.this.correlationHistoryRolloverPeriod = timeValue;
                            rescheduleCorrelationHistoryRollover();
                        });

        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        CORRELATION_HISTORY_RETENTION_PERIOD, this::setCorrelationHistoryRetentionPeriod);

        initFromClusterSettings();
    }

    private void populateAllIndexLists(List<String> logTypes) {
        List<HistoryIndexInfo> alertHistoryIndices = new ArrayList<>();
        List<HistoryIndexInfo> findingHistoryIndices = new ArrayList<>();

        logTypes.forEach(
                logType -> {
                    String alertsHistoryIndex = DetectorMonitorConfig.getAlertsHistoryIndex(logType);
                    String alertsHistoryIndexPattern =
                            DetectorMonitorConfig.getAlertsHistoryIndexPattern(logType);

                    alertHistoryIndices.add(
                            new HistoryIndexInfo(
                                    alertsHistoryIndex,
                                    alertsHistoryIndexPattern,
                                    alertMapping(),
                                    alertHistoryMaxDocs,
                                    alertHistoryMaxAge,
                                    clusterService.state().metadata().hasAlias(alertsHistoryIndex)));

                    String findingsIndex = DetectorMonitorConfig.getFindingsIndex(logType);
                    String findingsIndexPattern = DetectorMonitorConfig.getFindingsIndexPattern(logType);

                    findingHistoryIndices.add(
                            new HistoryIndexInfo(
                                    findingsIndex,
                                    findingsIndexPattern,
                                    findingMapping(),
                                    findingHistoryMaxDocs,
                                    findingHistoryMaxAge,
                                    clusterService.state().metadata().hasAlias(findingsIndex)));
                });

        this.alertHistoryIndices = alertHistoryIndices;
        this.findingHistoryIndices = findingHistoryIndices;
    }

    private void initFromClusterSettings() {
        alertHistoryEnabled = ALERT_HISTORY_ENABLED.get(settings);
        findingHistoryEnabled = FINDING_HISTORY_ENABLED.get(settings);
        alertHistoryMaxDocs = ALERT_HISTORY_MAX_DOCS.get(settings);
        findingHistoryMaxDocs = FINDING_HISTORY_MAX_DOCS.get(settings);
        correlationHistoryMaxDocs = CORRELATION_HISTORY_MAX_DOCS.get(settings);
        alertHistoryMaxAge = ALERT_HISTORY_INDEX_MAX_AGE.get(settings);
        findingHistoryMaxAge = FINDING_HISTORY_INDEX_MAX_AGE.get(settings);
        correlationHistoryMaxAge = CORRELATION_HISTORY_INDEX_MAX_AGE.get(settings);
        alertHistoryRolloverPeriod = ALERT_HISTORY_ROLLOVER_PERIOD.get(settings);
        findingHistoryRolloverPeriod = FINDING_HISTORY_ROLLOVER_PERIOD.get(settings);
        correlationHistoryRolloverPeriod = CORRELATION_HISTORY_ROLLOVER_PERIOD.get(settings);
        alertHistoryRetentionPeriod = ALERT_HISTORY_RETENTION_PERIOD.get(settings);
        findingHistoryRetentionPeriod = FINDING_HISTORY_RETENTION_PERIOD.get(settings);
        correlationHistoryRetentionPeriod = CORRELATION_HISTORY_RETENTION_PERIOD.get(settings);
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        // Instead of using a LocalNodeClusterManagerListener to track master changes, this service will
        // track them here to avoid conditions where master listener events run after other
        // listeners that depend on what happened in the master listener
        if (this.isClusterManager != event.localNodeClusterManager()) {
            this.isClusterManager = event.localNodeClusterManager();
            if (this.isClusterManager) {
                onMaster();
            } else {
                offMaster();
            }
        }
        for (HistoryIndexInfo h : alertHistoryIndices) {
            h.isInitialized = event.state().metadata().hasAlias(h.indexAlias);
        }
        for (HistoryIndexInfo h : findingHistoryIndices) {
            h.isInitialized = event.state().metadata().hasAlias(h.indexAlias);
        }

        if (correlationHistoryIndex != null && correlationHistoryIndex.indexAlias != null) {
            correlationHistoryIndex.isInitialized =
                    event.state().metadata().hasAlias(correlationHistoryIndex.indexAlias);
        }
    }

    private void onMaster() {
        try {
            // try to rollover immediately as we might be restarting the cluster
            threadPool.schedule(
                    () -> {
                        rolloverAndDeleteAlertHistoryIndices();
                        rolloverAndDeleteFindingHistoryIndices();
                        rolloverAndDeleteCorrelationHistoryIndices();
                    },
                    TimeValue.timeValueSeconds(1),
                    executorName());
            // schedule the next rollover for approx MAX_AGE later
            scheduledAlertsRollover =
                    threadPool.scheduleWithFixedDelay(
                            () -> rolloverAndDeleteAlertHistoryIndices(),
                            alertHistoryRolloverPeriod,
                            executorName());
            scheduledFindingsRollover =
                    threadPool.scheduleWithFixedDelay(
                            () -> rolloverAndDeleteFindingHistoryIndices(),
                            findingHistoryRolloverPeriod,
                            executorName());
            scheduledCorrelationHistoryRollover =
                    threadPool.scheduleWithFixedDelay(
                            () -> rolloverAndDeleteCorrelationHistoryIndices(),
                            correlationHistoryRolloverPeriod,
                            executorName());
        } catch (Exception e) {
            // This should be run on cluster startup
            logger.error(
                    "Error creating alert/finding/correlation indices. "
                            + "Alerts/Findings/Correlations can't be recorded until master node is restarted.",
                    e);
        }
    }

    private void offMaster() {
        if (scheduledAlertsRollover != null) {
            scheduledAlertsRollover.cancel();
        }
        if (scheduledFindingsRollover != null) {
            scheduledFindingsRollover.cancel();
        }
        if (scheduledCorrelationHistoryRollover != null) {
            scheduledCorrelationHistoryRollover.cancel();
        }
    }

    private String executorName() {
        return ThreadPool.Names.MANAGEMENT;
    }

    /**
     * Deletes the history indices of one kind that have outlived their retention period.
     *
     * @param tag the kind of history, for the logs.
     * @param historyIndex matches the names of that kind of history index, and nothing else.
     * @param retentionPeriod how long an index is kept after its creation.
     * @param writeAlias matches the write aliases of that kind of history.
     * @param historyEnabled whether that kind of history is enabled.
     */
    private void deleteOldIndices(
            String tag,
            Pattern historyIndex,
            TimeValue retentionPeriod,
            Pattern writeAlias,
            boolean historyEnabled) {
        List<String> indicesToDelete =
                selectExpiredHistoryIndices(
                        clusterService.state().metadata().indices().values(),
                        historyIndex,
                        Instant.now().toEpochMilli(),
                        retentionPeriod.millis(),
                        writeAlias,
                        historyEnabled);
        if (indicesToDelete.isEmpty()) {
            logger.debug("No old {} history indices to delete", tag);
            return;
        }
        logger.info("Deleting old {} history indices: {}", tag, indicesToDelete);
        deleteIndices(tag, indicesToDelete);
    }

    /**
     * Picks the history indices of one kind that have outlived their retention period.
     *
     * <p>Each kind is judged only against its own retention period and write aliases. The index
     * behind a write alias is still being written to, so it is kept while that history is enabled.
     *
     * @param indices every index in the cluster.
     * @param historyIndex matches the names of that kind of history index, and nothing else. It must
     *     not match an index that is not history, such as a detector's active alerts index: an index
     *     without a write alias is deleted once it is old enough.
     * @param nowMillis the current time.
     * @param retentionMillis how long an index is kept after its creation.
     * @param writeAlias matches the write aliases of that kind of history.
     * @param historyEnabled whether that kind of history is enabled.
     * @return the names of the indices to delete.
     */
    static List<String> selectExpiredHistoryIndices(
            Collection<IndexMetadata> indices,
            Pattern historyIndex,
            long nowMillis,
            long retentionMillis,
            Pattern writeAlias,
            boolean historyEnabled) {
        List<String> expired = new ArrayList<>();
        for (IndexMetadata index : indices) {
            String name = index.getIndex().getName();
            if (!historyIndex.matcher(name).matches()
                    || nowMillis - index.getCreationDate() <= retentionMillis) {
                continue;
            }
            boolean holdsWriteAlias =
                    index.getAliases().keySet().stream()
                            .anyMatch(alias -> writeAlias.matcher(alias).matches());
            if (holdsWriteAlias && historyEnabled) {
                continue;
            }
            expired.add(name);
        }
        return expired;
    }

    /**
     * Deletes the generations of detectors' dedicated query indices that nothing reads any more. See
     * {@link #selectUnusedQueryIndexGenerations}.
     */
    private void deleteUnusedQueryIndexGenerations() {
        try {
            List<String> unused =
                    selectUnusedQueryIndexGenerations(
                            clusterService.state().metadata().indices().values(),
                            Instant.now().toEpochMilli(),
                            QUERY_INDEX_GENERATION_GRACE_PERIOD.millis());
            if (unused.isEmpty()) {
                logger.debug("No unused detector query index generations to delete");
                return;
            }
            logger.info("Deleting detector query index generations no longer in use: {}", unused);
            deleteIndices("detector query index generation", unused);
        } catch (Exception e) {
            logger.warn("Could not delete unused detector query index generations", e);
        }
    }

    /**
     * Picks the generations of detectors' dedicated query indices that nothing reads any more.
     *
     * <p>Alerting rolls a detector's query index over when its mapping reaches the field limit. The
     * alias moves to the new generation and the old one is left without an alias. Security Analytics
     * creates a detector's monitors with {@code deleteQueryIndexInEveryRun}, so they resolve the
     * alias' write index on every run, and after that run nothing reads the old generation again.
     * Deleting a detector deletes only the generation behind the alias. Without this sweep, every
     * other generation is kept for good.
     *
     * <p>The grace period covers the run that rolled the index over, which may still percolate the
     * documents of another source index against the previous generation. It counts from the rollover,
     * or from the index creation when no rollover is recorded.
     *
     * @param indices every index in the cluster.
     * @param nowMillis the current time.
     * @param gracePeriodMillis how long a generation must have been out of use.
     * @return the names of the generations to delete.
     */
    static List<String> selectUnusedQueryIndexGenerations(
            Collection<IndexMetadata> indices, long nowMillis, long gracePeriodMillis) {
        List<String> unused = new ArrayList<>();
        for (IndexMetadata index : indices) {
            String name = index.getIndex().getName();
            if (!DEDICATED_QUERY_INDEX_GENERATION.matcher(name).matches()
                    || !index.getAliases().isEmpty()) {
                continue;
            }
            long lastUsed = index.getCreationDate();
            for (RolloverInfo rollover : index.getRolloverInfos().values()) {
                lastUsed = Math.max(lastUsed, rollover.getTime());
            }
            if (nowMillis - lastUsed > gracePeriodMillis) {
                unused.add(name);
            }
        }
        return unused;
    }

    private void deleteIndices(String tag, List<String> indices) {
        DeleteIndexRequest request =
                new DeleteIndexRequest(indices.toArray(new String[0]))
                        .indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN_CLOSED_HIDDEN);
        client
                .admin()
                .indices()
                .delete(
                        request,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(AcknowledgedResponse response) {
                                if (response.isAcknowledged()) {
                                    logger.info("Deleted {} indices: {}", tag, indices);
                                } else {
                                    logger.warn(
                                            "Deletion of {} indices {} was not acknowledged, retrying one by one",
                                            tag,
                                            indices);
                                    deleteIndicesOneByOne(tag, indices);
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                logger.warn("Could not delete {} indices {}, retrying one by one", tag, indices, e);
                                deleteIndicesOneByOne(tag, indices);
                            }
                        });
    }

    private void deleteIndicesOneByOne(String tag, List<String> indices) {
        for (String index : indices) {
            DeleteIndexRequest request =
                    new DeleteIndexRequest(index)
                            .indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN_CLOSED_HIDDEN);
            client
                    .admin()
                    .indices()
                    .delete(
                            request,
                            new ActionListener<>() {
                                @Override
                                public void onResponse(AcknowledgedResponse response) {
                                    if (!response.isAcknowledged()) {
                                        logger.warn("Deletion of {} index [{}] was not acknowledged", tag, index);
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    logger.warn("Could not delete {} index [{}]", tag, index, e);
                                }
                            });
        }
    }

    private void rolloverAndDeleteAlertHistoryIndices() {
        // Unrelated to alert history: it only shares this schedule instead of having one of its own.
        deleteUnusedQueryIndexGenerations();
        deleteOldIndices(
                "alert",
                ALERT_HISTORY_INDEX,
                alertHistoryRetentionPeriod,
                ALERT_HISTORY_WRITE_ALIAS,
                alertHistoryEnabled);
        logTypeService.getAllLogTypes(
                ActionListener.wrap(
                        logTypes -> {
                            if (logTypes == null || logTypes.isEmpty()) {
                                return;
                            }
                            // We have to do this every time to account for newly added log types
                            populateAllIndexLists(logTypes);

                            if (alertHistoryEnabled) rolloverAlertHistoryIndices();
                        },
                        e -> logger.warn("Could not roll over the alert history indices", e)));
    }

    private void rolloverAndDeleteFindingHistoryIndices() {
        deleteOldIndices(
                "finding",
                FINDING_HISTORY_INDEX,
                findingHistoryRetentionPeriod,
                FINDING_HISTORY_WRITE_ALIAS,
                findingHistoryEnabled);
        logTypeService.getAllLogTypes(
                ActionListener.wrap(
                        logTypes -> {
                            if (logTypes == null || logTypes.isEmpty()) {
                                return;
                            }
                            // We have to do this every time to account for newly added log types
                            populateAllIndexLists(logTypes);

                            if (findingHistoryEnabled) rolloverFindingHistoryIndices();
                        },
                        e -> logger.warn("Could not roll over the finding history indices", e)));
    }

    private void rolloverAndDeleteCorrelationHistoryIndices() {
        try {
            correlationHistoryIndex =
                    new HistoryIndexInfo(
                            CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX,
                            CorrelationIndices.CORRELATION_HISTORY_INDEX_PATTERN,
                            CorrelationIndices.correlationMappings(),
                            correlationHistoryMaxDocs,
                            correlationHistoryMaxAge,
                            clusterService
                                    .state()
                                    .metadata()
                                    .hasAlias(CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX));
            rolloverCorrelationHistoryIndices();
            deleteOldIndices(
                    "correlation",
                    CORRELATION_HISTORY_INDEX,
                    correlationHistoryRetentionPeriod,
                    CORRELATION_HISTORY_WRITE_ALIAS,
                    true);
        } catch (Exception ex) {
            logger.error("Could not roll over or delete the correlation history indices", ex);
        }
    }

    private void rolloverIndex(
            Boolean initialized,
            String index,
            String pattern,
            String map,
            Long docsCondition,
            TimeValue ageCondition,
            Boolean isCorrelation) {
        if (!initialized) {
            return;
        }

        // We have to pass null for newIndexName in order to get Elastic to increment the index count.
        RolloverRequest request = new RolloverRequest(index, null);
        request
                .getCreateIndexRequest()
                .index(pattern)
                .mapping(map)
                .settings(
                        isCorrelation
                                ? Settings.builder()
                                        .put("index.hidden", true)
                                        .put("index.correlation", true)
                                        .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                                        .put(
                                                "index.auto_expand_replicas",
                                                minSystemIndexReplicas + "-" + maxSystemIndexReplicas)
                                        .build()
                                : Settings.builder()
                                        .put("index.hidden", true)
                                        .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                                        .put(
                                                "index.auto_expand_replicas",
                                                minSystemIndexReplicas + "-" + maxSystemIndexReplicas)
                                        .build());
        request.addMaxIndexDocsCondition(docsCondition);
        request.addMaxIndexAgeCondition(ageCondition);
        client
                .admin()
                .indices()
                .rolloverIndex(
                        request,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(RolloverResponse rolloverResponse) {
                                if (!rolloverResponse.isRolledOver()) {
                                    logger.info(
                                            index
                                                    + "not rolled over. Conditions were: "
                                                    + rolloverResponse.getConditionStatus());
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                logger.error("rollover failed for index [" + index + "].");
                            }
                        });
    }

    private void rolloverAlertHistoryIndices() {
        for (HistoryIndexInfo h : alertHistoryIndices) {
            rolloverIndex(
                    h.isInitialized,
                    h.indexAlias,
                    h.indexPattern,
                    h.indexMappings,
                    h.maxDocs,
                    h.maxAge,
                    false);
        }
    }

    private void rolloverFindingHistoryIndices() {
        for (HistoryIndexInfo h : findingHistoryIndices) {
            rolloverIndex(
                    h.isInitialized,
                    h.indexAlias,
                    h.indexPattern,
                    h.indexMappings,
                    h.maxDocs,
                    h.maxAge,
                    false);
        }
    }

    private void rolloverCorrelationHistoryIndices() {
        if (correlationHistoryIndex != null) {
            rolloverIndex(
                    correlationHistoryIndex.isInitialized,
                    correlationHistoryIndex.indexAlias,
                    correlationHistoryIndex.indexPattern,
                    correlationHistoryIndex.indexMappings,
                    correlationHistoryIndex.maxDocs,
                    correlationHistoryIndex.maxAge,
                    true);
        }
    }

    private void rescheduleAlertRollover() {
        if (clusterService.state().getNodes().isLocalNodeElectedClusterManager()) {
            if (scheduledAlertsRollover != null) {
                scheduledAlertsRollover.cancel();
            }
            scheduledAlertsRollover =
                    threadPool.scheduleWithFixedDelay(
                            () -> rolloverAndDeleteAlertHistoryIndices(),
                            alertHistoryRolloverPeriod,
                            executorName());
        }
    }

    private void rescheduleFindingRollover() {
        if (clusterService.state().getNodes().isLocalNodeElectedClusterManager()) {
            if (scheduledFindingsRollover != null) {
                scheduledFindingsRollover.cancel();
            }
            scheduledFindingsRollover =
                    threadPool.scheduleWithFixedDelay(
                            () -> rolloverAndDeleteFindingHistoryIndices(),
                            findingHistoryRolloverPeriod,
                            executorName());
        }
    }

    private void rescheduleCorrelationHistoryRollover() {
        if (clusterService.state().getNodes().isLocalNodeElectedClusterManager()) {
            if (scheduledCorrelationHistoryRollover != null) {
                scheduledCorrelationHistoryRollover.cancel();
            }
            scheduledCorrelationHistoryRollover =
                    threadPool.scheduleWithFixedDelay(
                            () -> rolloverAndDeleteCorrelationHistoryIndices(),
                            correlationHistoryRolloverPeriod,
                            executorName());
        }
    }

    private String alertMapping() {
        String alertMapping = null;
        try (InputStream is =
                DetectorIndexManagementService.class
                        .getClassLoader()
                        .getResourceAsStream("mappings/alert_mapping.json")) {
            alertMapping = new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
        return alertMapping;
    }

    private String findingMapping() {
        String findingMapping = null;
        try (InputStream is =
                DetectorIndexManagementService.class
                        .getClassLoader()
                        .getResourceAsStream("mappings/finding_mapping.json")) {
            findingMapping =
                    new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
        return findingMapping;
    }

    // Setters

    public void setAlertHistoryEnabled(Boolean alertHistoryEnabled) {
        this.alertHistoryEnabled = alertHistoryEnabled;
    }

    public void setFindingHistoryEnabled(Boolean findingHistoryEnabled) {
        this.findingHistoryEnabled = findingHistoryEnabled;
    }

    public void setAlertHistoryMaxDocs(Long alertHistoryMaxDocs) {
        this.alertHistoryMaxDocs = alertHistoryMaxDocs;
    }

    public void setFindingHistoryMaxDocs(Long findingHistoryMaxDocs) {
        this.findingHistoryMaxDocs = findingHistoryMaxDocs;
    }

    public void setCorrelationHistoryMaxDocs(Long correlationHistoryMaxDocs) {
        this.correlationHistoryMaxDocs = correlationHistoryMaxDocs;
    }

    public void setAlertHistoryMaxAge(TimeValue alertHistoryMaxAge) {
        this.alertHistoryMaxAge = alertHistoryMaxAge;
    }

    public void setFindingHistoryMaxAge(TimeValue findingHistoryMaxAge) {
        this.findingHistoryMaxAge = findingHistoryMaxAge;
    }

    public void setCorrelationHistoryMaxAge(TimeValue correlationHistoryMaxAge) {
        this.correlationHistoryMaxAge = correlationHistoryMaxAge;
    }

    public void setAlertHistoryRolloverPeriod(TimeValue alertHistoryRolloverPeriod) {
        this.alertHistoryRolloverPeriod = alertHistoryRolloverPeriod;
    }

    public void setFindingHistoryRolloverPeriod(TimeValue findingHistoryRolloverPeriod) {
        this.findingHistoryRolloverPeriod = findingHistoryRolloverPeriod;
    }

    public void setCorrelationHistoryRolloverPeriod(TimeValue correlationHistoryRolloverPeriod) {
        this.correlationHistoryRolloverPeriod = correlationHistoryRolloverPeriod;
    }

    public void setAlertHistoryRetentionPeriod(TimeValue alertHistoryRetentionPeriod) {
        this.alertHistoryRetentionPeriod = alertHistoryRetentionPeriod;
    }

    public void setFindingHistoryRetentionPeriod(TimeValue findingHistoryRetentionPeriod) {
        this.findingHistoryRetentionPeriod = findingHistoryRetentionPeriod;
    }

    public void setCorrelationHistoryRetentionPeriod(TimeValue correlationHistoryRetentionPeriod) {
        this.correlationHistoryRetentionPeriod = correlationHistoryRetentionPeriod;
    }

    public void setClusterManager(boolean clusterManager) {
        isClusterManager = clusterManager;
    }

    @Override
    protected void doStart() {}

    @Override
    protected void doStop() {
        if (scheduledAlertsRollover != null) {
            scheduledAlertsRollover.cancel();
        }
        if (scheduledFindingsRollover != null) {
            scheduledFindingsRollover.cancel();
        }
        if (scheduledCorrelationHistoryRollover != null) {
            scheduledCorrelationHistoryRollover.cancel();
        }
    }

    @Override
    protected void doClose() {
        if (scheduledAlertsRollover != null) {
            scheduledAlertsRollover.cancel();
        }
        if (scheduledFindingsRollover != null) {
            scheduledFindingsRollover.cancel();
        }
        if (scheduledCorrelationHistoryRollover != null) {
            scheduledCorrelationHistoryRollover.cancel();
        }
    }

    private static class HistoryIndexInfo {

        String indexAlias;
        String indexPattern;
        String indexMappings;
        Long maxDocs;
        TimeValue maxAge;
        boolean isInitialized;

        public HistoryIndexInfo(
                String indexAlias,
                String indexPattern,
                String indexMappings,
                Long maxDocs,
                TimeValue maxAge,
                boolean isInitialized) {
            this.indexAlias = indexAlias;
            this.indexPattern = indexPattern;
            this.indexMappings = indexMappings;
            this.maxDocs = maxDocs;
            this.maxAge = maxAge;
            this.isInitialized = isInitialized;
        }
    }
}
