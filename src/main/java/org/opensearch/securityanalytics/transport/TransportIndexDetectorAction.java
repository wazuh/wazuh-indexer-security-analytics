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

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.commons.alerting.action.DeleteWorkflowResponse;
import org.opensearch.commons.alerting.action.IndexMonitorRequest;
import org.opensearch.commons.alerting.action.IndexMonitorResponse;
import org.opensearch.commons.alerting.action.IndexWorkflowResponse;
import org.opensearch.commons.alerting.model.BucketLevelTrigger;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.DocLevelMonitorInput;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.DocumentLevelTrigger;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Monitor.MonitorType;
import org.opensearch.commons.alerting.model.SearchInput;
import org.opensearch.commons.alerting.model.Workflow;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.RangeQueryBuilder;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.script.Script;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.GetIndexMappingsAction;
import org.opensearch.securityanalytics.action.GetIndexMappingsRequest;
import org.opensearch.securityanalytics.action.GetIndexMappingsResponse;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.mapper.MapperUtils;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.LogType;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.model.Value;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend.AggregationQueries;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.ExceptionChecker;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.MonitorService;
import org.opensearch.securityanalytics.util.ResourceLockService;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.securityanalytics.util.ThrowableCheckingPredicates;
import org.opensearch.securityanalytics.util.WorkflowService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class TransportIndexDetectorAction
        extends HandledTransportAction<IndexDetectorRequest, IndexDetectorResponse>
        implements SecureTransportAction {

    public static final String PLUGIN_OWNER_FIELD = "security_analytics";
    private static final Logger log = LogManager.getLogger(TransportIndexDetectorAction.class);
    public static final String TIMESTAMP_FIELD_ALIAS = "timestamp";
    public static final String CHAINED_FINDINGS_MONITOR_STRING = "chained_findings_monitor";

    /**
     * Thread context header used by internal Wazuh plugin callers (e.g. Content Manager) to bypass
     * standard-detector modification restrictions.
     */
    public static final String WAZUH_INTERNAL_CALLER_HEADER = "_wazuh_internal_caller";

    /** Lock ID guarding the {@code max_detectors} limit-check-then-create sequence. */
    private static final String MAX_DETECTORS_LOCK_ID = "security-analytics-max-detectors";

    /**
     * Error raised when a detector resolves to zero monitors (no compatible rules). Exposed so the
     * rule-update cascade can recognise this specific case and treat it as non-fatal (a detector
     * whose rules were all disabled is reconciled on the next promote), while still failing hard on
     * any other rebuild error.
     */
    static final String NO_COMPATIBLE_RULES_ERROR =
            "Detector cannot be created as no compatible rules were provided";

    static String validateSingleRuleSpace(Detector detector) {
        if (detector.getInputs().isEmpty()) {
            return null;
        }
        DetectorInput input = detector.getInputs().get(0);
        List<DetectorRule> prePackaged = input.getPrePackagedRules();
        List<DetectorRule> custom = input.getCustomRules();
        if (prePackaged != null && !prePackaged.isEmpty() && custom != null && !custom.isEmpty()) {
            return "Detector cannot have both prepackaged and custom rules. Use only one type.";
        }
        return null;
    }

    /**
     * Reads the top-level {@code enabled} flag from a rule's raw content blob.
     *
     * <p>{@code enabled} is a Wazuh-specific extension that is not part of the Sigma model nor an
     * indexed field on the rule document — it only lives inside the raw content blob (a JSON string).
     * This is fail-open on purpose: a missing field, a blank blob, or non-JSON content (e.g. a
     * pre-packaged rule loaded from disk as Sigma YAML, which carries no {@code enabled}) is treated
     * as enabled, so only rules that explicitly declare {@code enabled: false} are excluded.
     *
     * @param rawRuleContent the raw rule content (the {@code rule} field of the stored document)
     * @return {@code false} only when the blob explicitly declares {@code enabled} as false
     */
    static boolean isRuleEnabled(String rawRuleContent) {
        if (rawRuleContent == null || rawRuleContent.isBlank()) {
            return true;
        }
        try (XContentParser parser =
                XContentType.JSON
                        .xContent()
                        .createParser(
                                NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, rawRuleContent)) {
            Object enabled = parser.map().get("enabled");
            if (enabled instanceof Boolean) {
                return (Boolean) enabled;
            }
            if (enabled instanceof String) {
                return Boolean.parseBoolean((String) enabled);
            }
            return true;
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Returns only the rules whose content is not explicitly disabled, preserving order.
     *
     * <p>A detector must never compile a disabled rule into its Monitor: a disabled rule would still
     * match events and produce Findings, which is exactly the behaviour reported in issue #1394. This
     * is applied at the single point where all resolved rules (both pre-packaged and custom) converge
     * before query compilation, so it covers every detector create/update path.
     *
     * @param queries the resolved rules as (id, rule) pairs
     * @return the subset whose {@link #isRuleEnabled(String)} check passes
     */
    static List<Pair<String, Rule>> filterEnabledRules(List<Pair<String, Rule>> queries) {
        List<Pair<String, Rule>> enabled = new ArrayList<>();
        for (Pair<String, Rule> query : queries) {
            if (isRuleEnabled(query.getValue().getRule())) {
                enabled.add(query);
            } else {
                log.debug(
                        "Excluding disabled rule [{}] from detector query compilation",
                        query.getValue().getId());
            }
        }
        return enabled;
    }

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final DetectorIndices detectorIndices;

    private final RuleTopicIndices ruleTopicIndices;

    private final RuleIndices ruleIndices;

    private final MapperService mapperService;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private final LogTypeService logTypeService;

    private volatile Boolean filterByEnabled;

    private volatile Boolean enabledWorkflowUsage;

    private volatile Boolean enableDetectorWithDedicatedQueryIndices;

    private volatile int maxDetectors;

    private volatile int maxRulesPerDetector;

    private final Settings settings;

    private final NamedWriteableRegistry namedWriteableRegistry;

    private final WorkflowService workflowService;

    private final MonitorService monitorService;
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    private final ExceptionChecker exceptionChecker;

    private final TimeValue indexTimeout;

    private final ResourceLockService resourceLockService;

    @Inject
    public TransportIndexDetectorAction(
            TransportService transportService,
            Client client,
            ActionFilters actionFilters,
            NamedXContentRegistry xContentRegistry,
            DetectorIndices detectorIndices,
            RuleTopicIndices ruleTopicIndices,
            RuleIndices ruleIndices,
            MapperService mapperService,
            ClusterService clusterService,
            Settings settings,
            NamedWriteableRegistry namedWriteableRegistry,
            LogTypeService logTypeService,
            IndexNameExpressionResolver indexNameExpressionResolver,
            ExceptionChecker exceptionChecker) {
        super(IndexDetectorAction.NAME, transportService, actionFilters, IndexDetectorRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.detectorIndices = detectorIndices;
        this.ruleTopicIndices = ruleTopicIndices;
        this.ruleIndices = ruleIndices;
        this.mapperService = mapperService;
        this.clusterService = clusterService;
        this.settings = settings;
        this.namedWriteableRegistry = namedWriteableRegistry;
        this.logTypeService = logTypeService;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.threadPool = this.detectorIndices.getThreadPool();
        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.enabledWorkflowUsage = SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE.get(this.settings);
        this.enableDetectorWithDedicatedQueryIndices =
                SecurityAnalyticsSettings.ENABLE_DETECTORS_WITH_DEDICATED_QUERY_INDICES.get(this.settings);
        this.maxDetectors = SecurityAnalyticsSettings.MAX_DETECTORS.get(this.settings);
        this.maxRulesPerDetector = SecurityAnalyticsSettings.MAX_RULES_PER_DETECTOR.get(this.settings);
        this.monitorService = new MonitorService(client);
        this.workflowService = new WorkflowService(client, this.monitorService);
        this.resourceLockService = new ResourceLockService(client, clusterService, this.threadPool);

        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE, this::setEnabledWorkflowUsage);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.ENABLE_DETECTORS_WITH_DEDICATED_QUERY_INDICES,
                        this::setEnabledDetectorsWithDedicatedQueryIndices);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.MAX_DETECTORS, maxVal -> this.maxDetectors = maxVal);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.MAX_RULES_PER_DETECTOR,
                        maxVal -> this.maxRulesPerDetector = maxVal);
        this.exceptionChecker = exceptionChecker;
    }

    @Override
    protected void doExecute(
            Task task, IndexDetectorRequest request, ActionListener<IndexDetectorResponse> listener) {
        User user = this.readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = this.validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(
                    SecurityAnalyticsException.wrap(
                            new OpenSearchStatusException(validateBackendRoleMessage, RestStatus.FORBIDDEN)));
            return;
        }

        // Prevent detectors from exceeding the configured rules-per-detector limit.
        String ruleCountError =
                TransportIndexDetectorAction.validateRuleCount(
                        request.getDetector(), this.maxRulesPerDetector);
        if (ruleCountError != null) {
            listener.onFailure(
                    SecurityAnalyticsException.wrap(
                            new OpenSearchStatusException(ruleCountError, RestStatus.BAD_REQUEST)));
            return;
        }

        // Prevent modification of standard detectors
        // Use the flag from the request object — thread context headers don't survive
        // cross-action client.execute() calls (context is stashed by the transport layer).
        boolean isInternalCaller = request.isInternalCaller();
        // For non-internal callers, force source to custom
        if (!isInternalCaller) {
            request.getDetector().setSource(Detector.DEFAULT_SOURCE);
        }

        if (request.getMethod() == RestRequest.Method.PUT && !isInternalCaller) {
            // On update, check if the existing detector is a standard detector.
            // If so, only the enabled field can be changed by users.
            this.validateStandardDetectorUpdate(
                    request, listener, () -> this.checkIndicesAndExecute(task, request, listener, user));
        } else if (request.getMethod() == RestRequest.Method.POST && !isInternalCaller) {
            // On create, serialize the limit-check-then-create sequence so concurrent requests
            // cannot all observe a stale count and overshoot max_detectors. The lock is released
            // via the wrapped listener once the whole (async) creation pipeline completes.
            this.resourceLockService.acquire(
                    MAX_DETECTORS_LOCK_ID,
                    ActionListener.wrap(
                            lockId -> {
                                ActionListener<IndexDetectorResponse> releasingListener =
                                        ActionListener.runAfter(
                                                listener, () -> this.resourceLockService.release(lockId));
                                this.validateMaxDetectors(
                                        releasingListener,
                                        () -> this.checkIndicesAndExecute(task, request, releasingListener, user));
                            },
                            e -> listener.onFailure(SecurityAnalyticsException.wrap(e))));
        } else {
            this.checkIndicesAndExecute(task, request, listener, user);
        }
    }

    /**
     * Validates that creating a new detector would not exceed the configured maximum number of
     * user-created detectors ({@code plugins.security_analytics.max_detectors}). Standard detectors
     * (source = "standard") are excluded from the count.
     *
     * @param listener the action listener to notify on failure
     * @param onSuccess the continuation to run if the limit is not exceeded
     */
    private void validateMaxDetectors(
            ActionListener<IndexDetectorResponse> listener, Runnable onSuccess) {
        SearchRequest searchRequest = new SearchRequest(Detector.DETECTORS_INDEX);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(
                QueryBuilders.boolQuery()
                        .mustNot(
                                QueryBuilders.nestedQuery(
                                        "detector",
                                        QueryBuilders.termQuery(
                                                "detector." + Detector.SOURCE_FIELD, Detector.STANDARD_SOURCE),
                                        org.apache.lucene.search.join.ScoreMode.None)));
        searchSourceBuilder.size(0);
        searchSourceBuilder.trackTotalHits(true);
        searchRequest.source(searchSourceBuilder);

        this.client.search(
                searchRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        long count =
                                response.getHits().getTotalHits() != null
                                        ? response.getHits().getTotalHits().value()
                                        : 0;
                        if (count >= TransportIndexDetectorAction.this.maxDetectors) {
                            log.info(
                                    "This request would create more than the allowed detectors [{}].",
                                    TransportIndexDetectorAction.this.maxDetectors);
                            listener.onFailure(
                                    SecurityAnalyticsException.wrap(
                                            new OpenSearchStatusException(
                                                    "This request would create more than the allowed detectors ["
                                                            + TransportIndexDetectorAction.this.maxDetectors
                                                            + "].",
                                                    RestStatus.BAD_REQUEST)));
                        } else {
                            onSuccess.run();
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        // If the detectors index does not exist yet, there are no detectors.
                        log.warn("Failed to count existing detectors for limit check", e);
                        onSuccess.run();
                    }
                });
    }

    /**
     * Returns true if the only difference between the existing and incoming detector is the {@code
     * enabled} field (and its derived {@code enabledTime}/{@code lastUpdateTime}). Any change to
     * name, inputs/rules, triggers, or threat intel is considered a modification and will be rejected
     * for standard detectors.
     */
    private static boolean isOnlyEnabledChange(Detector existing, Detector incoming) {
        return Objects.equals(existing.getName(), incoming.getName())
                && Objects.equals(existing.getDetectorType(), incoming.getDetectorType())
                && Objects.equals(existing.getThreatIntelEnabled(), incoming.getThreatIntelEnabled())
                && Objects.equals(existing.getInputs(), incoming.getInputs())
                && Objects.equals(existing.getTriggers(), incoming.getTriggers());
    }

    /**
     * Validates that a user update to a standard detector only changes the enabled field. If the
     * detector is not standard, or the update is valid, the provided continuation is run.
     */
    private void validateStandardDetectorUpdate(
            IndexDetectorRequest request,
            ActionListener<IndexDetectorResponse> listener,
            Runnable onValid) {
        String detectorId = request.getDetectorId();
        GetRequest getRequest = new GetRequest(Detector.DETECTORS_INDEX, detectorId);
        this.client.get(
                getRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetResponse response) {
                        if (!response.isExists()) {
                            onValid.run();
                            return;
                        }
                        try {
                            XContentParser xcp =
                                    XContentHelper.createParser(
                                            TransportIndexDetectorAction.this.xContentRegistry,
                                            LoggingDeprecationHandler.INSTANCE,
                                            response.getSourceAsBytesRef(),
                                            XContentType.JSON);
                            Detector existingDetector = Detector.docParse(xcp, detectorId, response.getVersion());

                            if (existingDetector.isStandardDetector()) {
                                // For standard detectors, users can only toggle enabled.
                                // Reject if any other user-visible field was changed.
                                Detector incoming = request.getDetector();
                                if (!TransportIndexDetectorAction.isOnlyEnabledChange(existingDetector, incoming)) {
                                    listener.onFailure(
                                            new OpenSearchStatusException(
                                                    "Standard detectors cannot be modified by users. "
                                                            + "Only enabling or disabling is allowed.",
                                                    RestStatus.BAD_REQUEST));
                                    return;
                                }
                                // Apply only the enabled toggle on top of the existing
                                // detector to prevent any silent field mutations.
                                boolean newEnabled = incoming.getEnabled();
                                existingDetector.setEnabled(newEnabled);
                                existingDetector.setEnabledTime(newEnabled ? Instant.now() : null);
                                existingDetector.setLastUpdateTime(Instant.now());
                                request.setDetector(existingDetector);
                                onValid.run();
                                return;
                            }
                            // Not a standard detector allow the update
                            // Preserve the source from the existing detector
                            request.getDetector().setSource(existingDetector.getSource());
                            onValid.run();
                        } catch (IOException e) {
                            listener.onFailure(e);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
    }

    /**
     * Returns an error message if any detector input exceeds the maximum allowed rule count, or
     * {@code null} if all inputs are within the limit.
     */
    static String validateRuleCount(Detector detector, int maxRulesPerDetector) {
        for (DetectorInput input : detector.getInputs()) {
            int ruleCount = Math.max(input.getCustomRules().size(), input.getPrePackagedRules().size());
            if (ruleCount > maxRulesPerDetector) {
                return String.format(
                        Locale.ROOT,
                        "Detector cannot have more than %d rules, but found %d",
                        maxRulesPerDetector,
                        ruleCount);
            }
        }
        return null;
    }

    /**
     * Validates detector input data sources before detector creation/update.
     *
     * <p>Threat detectors can only be created for data sources whose names start with {@code
     * wazuh-events-v5}. If any source does not match this prefix, the request is rejected with {@code
     * 400 Bad Request}.
     */
    private void checkIndicesAndExecute(
            Task task,
            IndexDetectorRequest request,
            ActionListener<IndexDetectorResponse> listener,
            User user) {
        log.debug("check indices and execute began");
        String[] detectorIndices =
                request.getDetector().getInputs().stream()
                        .flatMap(detectorInput -> detectorInput.getIndices().stream())
                        .toArray(String[]::new);

        boolean hasInvalidSource =
                Arrays.stream(detectorIndices).anyMatch(index -> !index.startsWith("wazuh-events-v5"));

        if (hasInvalidSource) {
            listener.onFailure(
                    new OpenSearchStatusException(
                            "Threat detectors can only be created for `wazuh-events-v5` data sources.",
                            RestStatus.BAD_REQUEST));
            return;
        }

        SearchRequest searchRequest =
                new SearchRequest(detectorIndices)
                        .source(
                                SearchSourceBuilder.searchSource().size(1).query(QueryBuilders.matchAllQuery()));
        searchRequest.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30));
        this.client.search(
                searchRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse searchResponse) {
                        log.debug(
                                "check indices and execute completed. Took {} millis",
                                searchResponse.getTook().millis());
                        AsyncIndexDetectorsAction asyncAction =
                                new AsyncIndexDetectorsAction(user, task, request, listener);
                        asyncAction.start();
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.debug("check indices and execute failed", e);
                        if (e instanceof OpenSearchStatusException) {
                            listener.onFailure(
                                    SecurityAnalyticsException.wrap(
                                            new OpenSearchStatusException(
                                                    String.format(
                                                            Locale.getDefault(),
                                                            "User doesn't have read permissions for one or more configured index %s",
                                                            (Object) detectorIndices),
                                                    RestStatus.FORBIDDEN)));
                        } else if (e instanceof IndexNotFoundException) {
                            listener.onFailure(
                                    SecurityAnalyticsException.wrap(
                                            new OpenSearchStatusException(
                                                    String.format(
                                                            Locale.getDefault(),
                                                            "Indices not found %s",
                                                            String.join(", ", detectorIndices)),
                                                    RestStatus.NOT_FOUND)));
                        } else {
                            listener.onFailure(SecurityAnalyticsException.wrap(e));
                        }
                    }
                });
    }

    private void createMonitorFromQueries(
            List<Pair<String, Rule>> rulesById,
            Detector detector,
            ActionListener<List<IndexMonitorResponse>> listener,
            WriteRequest.RefreshPolicy refreshPolicy,
            List<String> queryFieldNames) {
        List<Pair<String, Rule>> docLevelRules =
                rulesById.stream()
                        .filter(it -> !it.getRight().isAggregationRule())
                        .collect(Collectors.toList());
        List<Pair<String, Rule>> bucketLevelRules =
                rulesById.stream()
                        .filter(it -> it.getRight().isAggregationRule())
                        .collect(Collectors.toList());

        this.addThreatIntelBasedDocLevelQueries(
                detector,
                new ActionListener<>() {
                    @Override
                    public void onResponse(List<DocLevelQuery> dlqs) {
                        try {
                            List<IndexMonitorRequest> monitorRequests = new ArrayList<>();

                            if (!docLevelRules.isEmpty() || detector.getThreatIntelEnabled()) {
                                monitorRequests.add(
                                        TransportIndexDetectorAction.this.createDocLevelMonitorRequest(
                                                docLevelRules,
                                                dlqs != null ? dlqs : List.of(),
                                                detector,
                                                refreshPolicy,
                                                Monitor.NO_ID,
                                                Method.POST,
                                                queryFieldNames));
                            }

                            if (!bucketLevelRules.isEmpty()) {
                                StepListener<List<IndexMonitorRequest>> bucketLevelMonitorRequests =
                                        new StepListener<>();
                                TransportIndexDetectorAction.this.buildBucketLevelMonitorRequests(
                                        bucketLevelRules,
                                        detector,
                                        refreshPolicy,
                                        Monitor.NO_ID,
                                        Method.POST,
                                        bucketLevelMonitorRequests);
                                bucketLevelMonitorRequests.whenComplete(
                                        indexMonitorRequests -> {
                                            log.debug("bucket level monitor request built");
                                            monitorRequests.addAll(indexMonitorRequests);
                                            // Do nothing if detector doesn't have any monitor
                                            if (monitorRequests.isEmpty()) {
                                                listener.onResponse(Collections.emptyList());
                                                return;
                                            }

                                            List<IndexMonitorResponse> monitorResponses = new ArrayList<>();
                                            StepListener<IndexMonitorResponse> addFirstMonitorStep = new StepListener();

                                            // Indexing monitors in two steps in order to prevent all shards failed error
                                            // from alerting
                                            // https://github.com/opensearch-project/alerting/issues/646
                                            AlertingPluginInterface.INSTANCE.indexMonitor(
                                                    (NodeClient) TransportIndexDetectorAction.this.client,
                                                    monitorRequests.get(0),
                                                    TransportIndexDetectorAction.this.namedWriteableRegistry,
                                                    addFirstMonitorStep);
                                            addFirstMonitorStep.whenComplete(
                                                    addedFirstMonitorResponse -> {
                                                        log.debug(
                                                                "first monitor created id {} of type {}",
                                                                addedFirstMonitorResponse.getId(),
                                                                addedFirstMonitorResponse.getMonitor().getMonitorType());
                                                        monitorResponses.add(addedFirstMonitorResponse);

                                                        StepListener<List<IndexMonitorResponse>> indexMonitorsStep =
                                                                new StepListener<>();
                                                        indexMonitorsStep.whenComplete(
                                                                indexMonitorResponses ->
                                                                        TransportIndexDetectorAction.this.saveWorkflow(
                                                                                rulesById,
                                                                                detector,
                                                                                indexMonitorResponses,
                                                                                refreshPolicy,
                                                                                listener),
                                                                e -> {
                                                                    log.error("Failed to index the workflow: {}", e.getMessage());
                                                                    listener.onFailure(e);
                                                                });

                                                        int numberOfUnprocessedResponses = monitorRequests.size() - 1;
                                                        if (numberOfUnprocessedResponses == 0) {
                                                            TransportIndexDetectorAction.this.saveWorkflow(
                                                                    rulesById, detector, monitorResponses, refreshPolicy, listener);
                                                        } else {
                                                            // Saves the rest of the monitors and saves the workflow if supported
                                                            TransportIndexDetectorAction.this.saveMonitors(
                                                                    monitorRequests,
                                                                    monitorResponses,
                                                                    numberOfUnprocessedResponses,
                                                                    indexMonitorsStep);
                                                        }
                                                    },
                                                    e1 -> {
                                                        log.error(
                                                                "Failed to index doc level monitor in detector creation: {}",
                                                                e1.getMessage());
                                                        listener.onFailure(e1);
                                                    });
                                        },
                                        listener::onFailure);
                            } else {
                                // Failure if detector doesn't have any monitor
                                if (monitorRequests.isEmpty()) {
                                    listener.onFailure(
                                            new OpenSearchStatusException(
                                                    NO_COMPATIBLE_RULES_ERROR, RestStatus.BAD_REQUEST));
                                    return;
                                }

                                List<IndexMonitorResponse> monitorResponses = new ArrayList<>();
                                StepListener<IndexMonitorResponse> indexDocLevelMonitorStep = new StepListener();

                                // Indexing monitors in two steps in order to prevent all shards failed error from
                                // alerting
                                // https://github.com/opensearch-project/alerting/issues/646
                                AlertingPluginInterface.INSTANCE.indexMonitor(
                                        (NodeClient) TransportIndexDetectorAction.this.client,
                                        monitorRequests.get(0),
                                        TransportIndexDetectorAction.this.namedWriteableRegistry,
                                        indexDocLevelMonitorStep);
                                indexDocLevelMonitorStep.whenComplete(
                                        addedFirstMonitorResponse -> {
                                            monitorResponses.add(addedFirstMonitorResponse);
                                            TransportIndexDetectorAction.this.saveWorkflow(
                                                    rulesById, detector, monitorResponses, refreshPolicy, listener);
                                        },
                                        e -> {
                                            listener.onFailure(e);
                                        });
                            }
                        } catch (Exception ex) {
                            this.onFailure(ex);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        // not failing detector creation if any fatal exception occurs during doc level query
                        // creation from threat intel feed data
                        log.error(
                                "Failed to convert threat intel feed to. Proceeding with detector creation: {}",
                                e.getMessage());
                        listener.onFailure(e);
                    }
                });
    }

    private void saveMonitors(
            List<IndexMonitorRequest> monitorRequests,
            List<IndexMonitorResponse> monitorResponses,
            int numberOfUnprocessedResponses,
            ActionListener<List<IndexMonitorResponse>> listener) {
        GroupedActionListener<IndexMonitorResponse> monitorResponseListener =
                new GroupedActionListener(
                        new ActionListener<Collection<IndexMonitorResponse>>() {
                            @Override
                            public void onResponse(Collection<IndexMonitorResponse> indexMonitorResponses) {
                                monitorResponses.addAll(
                                        indexMonitorResponses.stream().collect(Collectors.toList()));
                                listener.onResponse(monitorResponses);
                            }

                            @Override
                            public void onFailure(Exception e) {
                                listener.onFailure(e);
                            }
                        },
                        numberOfUnprocessedResponses);

        for (int i = 1; i < monitorRequests.size(); i++) {
            AlertingPluginInterface.INSTANCE.indexMonitor(
                    (NodeClient) this.client,
                    monitorRequests.get(i),
                    this.namedWriteableRegistry,
                    monitorResponseListener);
        }
    }

    /**
     * If the workflow is enabled, saves the workflow, updates the detector and returns the saved
     * monitors if not, returns the saved monitors
     *
     * @param rulesById
     * @param detector
     * @param monitorResponses
     * @param refreshPolicy
     * @param actionListener
     */
    private void saveWorkflow(
            List<Pair<String, Rule>> rulesById,
            Detector detector,
            List<IndexMonitorResponse> monitorResponses,
            RefreshPolicy refreshPolicy,
            ActionListener<List<IndexMonitorResponse>> actionListener) {
        if (this.enabledWorkflowUsage) {
            this.workflowService.upsertWorkflow(
                    rulesById,
                    monitorResponses,
                    null,
                    detector,
                    refreshPolicy,
                    Workflow.NO_ID,
                    Method.POST,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(IndexWorkflowResponse workflowResponse) {
                            // Update passed detector with the workflowId
                            detector.setWorkflowIds(List.of(workflowResponse.getId()));
                            actionListener.onResponse(monitorResponses);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Error saving workflow: {}", e.getMessage());
                            actionListener.onFailure(e);
                        }
                    });
        } else {
            actionListener.onResponse(monitorResponses);
        }
    }

    private void updateMonitorFromQueries(
            String index,
            List<Pair<String, Rule>> rulesById,
            Detector detector,
            ActionListener<List<IndexMonitorResponse>> listener,
            WriteRequest.RefreshPolicy refreshPolicy,
            List<String> queryFieldNames) {
        List<IndexMonitorRequest> monitorsToBeUpdated = new ArrayList<>();

        List<Pair<String, Rule>> bucketLevelRules =
                rulesById.stream()
                        .filter(it -> it.getRight().isAggregationRule())
                        .collect(Collectors.toList());

        this.addThreatIntelBasedDocLevelQueries(
                detector,
                new ActionListener<>() {
                    @Override
                    public void onResponse(List<DocLevelQuery> docLevelQueries) {
                        List<IndexMonitorRequest> monitorsToBeAdded = new ArrayList<>();
                        // Process bucket level monitors
                        if (!bucketLevelRules.isEmpty()) {
                            TransportIndexDetectorAction.this.logTypeService.getRuleFieldMappings(
                                    new ActionListener<>() {
                                        @Override
                                        public void onResponse(Map<String, Map<String, String>> ruleFieldMappings) {
                                            try {
                                                List<String> ruleCategories =
                                                        bucketLevelRules.stream()
                                                                .map(Pair::getRight)
                                                                .map(Rule::getCategory)
                                                                .distinct()
                                                                .collect(Collectors.toList());
                                                Map<String, QueryBackend> queryBackendMap = new HashMap<>();
                                                for (String category : ruleCategories) {
                                                    Map<String, String> fieldMappings = ruleFieldMappings.get(category);
                                                    queryBackendMap.put(
                                                            category, new OSQueryBackend(fieldMappings, true, true));
                                                }

                                                // Pair of RuleId - MonitorId for existing monitors of the detector
                                                Map<String, String> monitorPerRule = detector.getRuleIdMonitorIdMap();
                                                GroupedActionListener<IndexMonitorRequest> groupedActionListener =
                                                        new GroupedActionListener<>(
                                                                new ActionListener<>() {
                                                                    @Override
                                                                    public void onResponse(
                                                                            Collection<IndexMonitorRequest> indexMonitorRequests) {
                                                                        if (detector
                                                                                .getRuleIdMonitorIdMap()
                                                                                .containsKey(CHAINED_FINDINGS_MONITOR_STRING)) {
                                                                            String cmfId =
                                                                                    detector
                                                                                            .getRuleIdMonitorIdMap()
                                                                                            .get(CHAINED_FINDINGS_MONITOR_STRING);
                                                                            if (TransportIndexDetectorAction.this
                                                                                    .shouldAddChainedFindingDocMonitor(
                                                                                            indexMonitorRequests.isEmpty(), rulesById)) {
                                                                                monitorsToBeUpdated.add(
                                                                                        TransportIndexDetectorAction.this
                                                                                                .createDocLevelMonitorMatchAllRequest(
                                                                                                        detector,
                                                                                                        RefreshPolicy.IMMEDIATE,
                                                                                                        cmfId,
                                                                                                        Method.PUT,
                                                                                                        rulesById));
                                                                            }
                                                                        } else {
                                                                            if (TransportIndexDetectorAction.this
                                                                                    .shouldAddChainedFindingDocMonitor(
                                                                                            indexMonitorRequests.isEmpty(), rulesById)) {
                                                                                monitorsToBeAdded.add(
                                                                                        TransportIndexDetectorAction.this
                                                                                                .createDocLevelMonitorMatchAllRequest(
                                                                                                        detector,
                                                                                                        RefreshPolicy.IMMEDIATE,
                                                                                                        detector.getId() + "_chained_findings",
                                                                                                        Method.POST,
                                                                                                        rulesById));
                                                                            }
                                                                        }
                                                                        TransportIndexDetectorAction.this.onIndexMonitorRequestCreation(
                                                                                monitorsToBeUpdated,
                                                                                monitorsToBeAdded,
                                                                                rulesById,
                                                                                detector,
                                                                                refreshPolicy,
                                                                                docLevelQueries,
                                                                                queryFieldNames,
                                                                                listener);
                                                                    }

                                                                    @Override
                                                                    public void onFailure(Exception e) {
                                                                        listener.onFailure(e);
                                                                    }
                                                                },
                                                                bucketLevelRules.size());
                                                for (Pair<String, Rule> query : bucketLevelRules) {
                                                    Rule rule = query.getRight();
                                                    if (rule.getAggregationQueries() != null) {
                                                        // Detect if the monitor should be added or updated
                                                        if (monitorPerRule.containsKey(rule.getId())) {
                                                            String monitorId = monitorPerRule.get(rule.getId());
                                                            TransportIndexDetectorAction.this.createBucketLevelMonitorRequest(
                                                                    query.getRight(),
                                                                    detector,
                                                                    refreshPolicy,
                                                                    monitorId,
                                                                    Method.PUT,
                                                                    queryBackendMap.get(rule.getCategory()),
                                                                    new ActionListener<>() {
                                                                        @Override
                                                                        public void onResponse(
                                                                                IndexMonitorRequest indexMonitorRequest) {
                                                                            monitorsToBeUpdated.add(indexMonitorRequest);
                                                                            groupedActionListener.onResponse(indexMonitorRequest);
                                                                        }

                                                                        @Override
                                                                        public void onFailure(Exception e) {
                                                                            log.error(
                                                                                    "Failed to create bucket level monitor request: {}",
                                                                                    e.getMessage());
                                                                            listener.onFailure(e);
                                                                        }
                                                                    });
                                                        } else {
                                                            TransportIndexDetectorAction.this.createBucketLevelMonitorRequest(
                                                                    query.getRight(),
                                                                    detector,
                                                                    refreshPolicy,
                                                                    Monitor.NO_ID,
                                                                    Method.POST,
                                                                    queryBackendMap.get(rule.getCategory()),
                                                                    new ActionListener<>() {
                                                                        @Override
                                                                        public void onResponse(
                                                                                IndexMonitorRequest indexMonitorRequest) {
                                                                            monitorsToBeAdded.add(indexMonitorRequest);
                                                                            groupedActionListener.onResponse(indexMonitorRequest);
                                                                        }

                                                                        @Override
                                                                        public void onFailure(Exception e) {
                                                                            log.error(
                                                                                    "Failed to create bucket level monitor request: {}",
                                                                                    e.getMessage());
                                                                            listener.onFailure(e);
                                                                        }
                                                                    });
                                                        }
                                                    }
                                                }

                                            } catch (Exception ex) {
                                                listener.onFailure(ex);
                                            }
                                        }

                                        @Override
                                        public void onFailure(Exception e) {
                                            listener.onFailure(e);
                                        }
                                    });
                        } else {
                            TransportIndexDetectorAction.this.onIndexMonitorRequestCreation(
                                    monitorsToBeUpdated,
                                    monitorsToBeAdded,
                                    rulesById,
                                    detector,
                                    refreshPolicy,
                                    docLevelQueries,
                                    queryFieldNames,
                                    listener);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
    }

    private boolean shouldAddChainedFindingDocMonitor(
            boolean bucketLevelMonitorsExist, List<Pair<String, Rule>> rulesById) {
        return this.enabledWorkflowUsage
                && !bucketLevelMonitorsExist
                && rulesById.stream().anyMatch(it -> it.getRight().isAggregationRule());
    }

    private void onIndexMonitorRequestCreation(
            List<IndexMonitorRequest> monitorsToBeUpdated,
            List<IndexMonitorRequest> monitorsToBeAdded,
            List<Pair<String, Rule>> rulesById,
            Detector detector,
            RefreshPolicy refreshPolicy,
            List<DocLevelQuery> docLevelQueries,
            List<String> queryFieldNames,
            ActionListener<List<IndexMonitorResponse>> listener) {
        List<Pair<String, Rule>> docLevelRules =
                rulesById.stream()
                        .filter(it -> !it.getRight().isAggregationRule())
                        .collect(Collectors.toList());

        // Process doc level monitors
        if (!docLevelRules.isEmpty() || detector.getThreatIntelEnabled()) {
            if (detector.getDocLevelMonitorId() == null) {
                monitorsToBeAdded.add(
                        this.createDocLevelMonitorRequest(
                                docLevelRules,
                                docLevelQueries != null ? docLevelQueries : List.of(),
                                detector,
                                refreshPolicy,
                                Monitor.NO_ID,
                                Method.POST,
                                queryFieldNames));
            } else {
                monitorsToBeUpdated.add(
                        this.createDocLevelMonitorRequest(
                                docLevelRules,
                                docLevelQueries != null ? docLevelQueries : List.of(),
                                detector,
                                refreshPolicy,
                                detector.getDocLevelMonitorId(),
                                Method.PUT,
                                queryFieldNames));
            }
        }

        List<String> monitorIdsToBeDeleted =
                detector.getRuleIdMonitorIdMap().values().stream().collect(Collectors.toList());
        monitorIdsToBeDeleted.removeAll(
                monitorsToBeUpdated.stream()
                        .map(IndexMonitorRequest::getMonitorId)
                        .collect(Collectors.toList()));

        this.updateAlertingMonitors(
                rulesById,
                detector,
                monitorsToBeAdded,
                monitorsToBeUpdated,
                monitorIdsToBeDeleted,
                refreshPolicy,
                listener);
    }

    /**
     * Update list of monitors for the given detector Executed in a steps: 1. Add new monitors; 2.
     * Update existing monitors; 3. Updates the workflow 4. Delete the monitors omitted from request
     * 5. Respond with updated list of monitors
     *
     * @param monitorsToBeAdded Newly added monitors by the user
     * @param monitorsToBeUpdated Existing monitors that will be updated
     * @param monitorsToBeDeleted Monitors omitted by the user
     * @param refreshPolicy
     * @param listener Listener that accepts the list of updated monitors if the action was successful
     */
    private void updateAlertingMonitors(
            List<Pair<String, Rule>> rulesById,
            Detector detector,
            List<IndexMonitorRequest> monitorsToBeAdded,
            List<IndexMonitorRequest> monitorsToBeUpdated,
            List<String> monitorsToBeDeleted,
            RefreshPolicy refreshPolicy,
            ActionListener<List<IndexMonitorResponse>> listener) {
        List<IndexMonitorResponse> updatedMonitors = new ArrayList<>();

        // Update monitor steps
        StepListener<List<IndexMonitorResponse>> addNewMonitorsStep = new StepListener();
        this.executeMonitorActionRequest(monitorsToBeAdded, addNewMonitorsStep);
        // 1. Add new alerting monitors (for the rules that didn't exist previously)
        addNewMonitorsStep.whenComplete(
                addNewMonitorsResponse -> {
                    if (addNewMonitorsResponse != null && !addNewMonitorsResponse.isEmpty()) {
                        updatedMonitors.addAll(addNewMonitorsResponse);
                    }
                    StepListener<List<IndexMonitorResponse>> updateMonitorsStep = new StepListener<>();
                    this.executeMonitorActionRequest(monitorsToBeUpdated, updateMonitorsStep);
                    // 2. Update existing alerting monitors (based on the common rules)
                    updateMonitorsStep.whenComplete(
                            updateMonitorResponse -> {
                                if (updateMonitorResponse != null && !updateMonitorResponse.isEmpty()) {
                                    updatedMonitors.addAll(updateMonitorResponse);
                                }
                                if (detector.isWorkflowSupported() && this.enabledWorkflowUsage) {
                                    this.updateWorkflowStep(
                                            rulesById,
                                            detector,
                                            monitorsToBeDeleted,
                                            refreshPolicy,
                                            listener,
                                            updatedMonitors,
                                            addNewMonitorsResponse,
                                            updateMonitorResponse);
                                } else {
                                    this.deleteMonitorStep(
                                            monitorsToBeDeleted, refreshPolicy, updatedMonitors, listener);
                                }
                            },
                            // Handle update monitor failed (step 2)
                            listener::onFailure);
                    // Handle add failed (step 1)
                },
                listener::onFailure);
    }

    private void deleteMonitorStep(
            List<String> monitorsToBeDeleted,
            RefreshPolicy refreshPolicy,
            List<IndexMonitorResponse> updatedMonitors,
            ActionListener<List<IndexMonitorResponse>> listener) {
        this.monitorService.deleteAlertingMonitors(
                monitorsToBeDeleted,
                refreshPolicy,
                new ActionListener<>() {
                    @Override
                    public void onResponse(List<DeleteMonitorResponse> deleteMonitorResponses) {
                        listener.onResponse(updatedMonitors);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to delete the monitors: {}", e.getMessage());
                        listener.onFailure(e);
                    }
                });
    }

    private void updateWorkflowStep(
            List<Pair<String, Rule>> rulesById,
            Detector detector,
            List<String> monitorsToBeDeleted,
            RefreshPolicy refreshPolicy,
            ActionListener<List<IndexMonitorResponse>> listener,
            List<IndexMonitorResponse> updatedMonitors,
            List<IndexMonitorResponse> addNewMonitorsResponse,
            List<IndexMonitorResponse> updateMonitorResponse) {
        List<String> addedMonitorIds =
                addNewMonitorsResponse.stream()
                        .map(IndexMonitorResponse::getId)
                        .collect(Collectors.toList());
        List<String> updatedMonitorIds =
                updateMonitorResponse.stream()
                        .map(IndexMonitorResponse::getId)
                        .collect(Collectors.toList());

        // If there are no added or updated monitors - all monitors should be deleted
        // Before deleting the monitors, workflow should be removed so there are no monitors that are
        // part of the workflow
        // which means that the workflow should be removed
        if (addedMonitorIds.isEmpty() && updatedMonitorIds.isEmpty()) {
            this.workflowService.deleteWorkflow(
                    detector.getWorkflowIds().get(0),
                    new ActionListener<>() {
                        @Override
                        public void onResponse(DeleteWorkflowResponse deleteWorkflowResponse) {
                            detector.setWorkflowIds(Collections.emptyList());
                            TransportIndexDetectorAction.this.deleteMonitorStep(
                                    monitorsToBeDeleted, refreshPolicy, updatedMonitors, listener);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to delete the workflow: {}", e.getMessage());
                            listener.onFailure(e);
                        }
                    });

        } else {
            // Update workflow and delete the monitors
            this.workflowService.upsertWorkflow(
                    rulesById,
                    addNewMonitorsResponse,
                    updateMonitorResponse,
                    detector,
                    refreshPolicy,
                    detector.getWorkflowIds().get(0),
                    Method.PUT,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(IndexWorkflowResponse workflowResponse) {
                            TransportIndexDetectorAction.this.deleteMonitorStep(
                                    monitorsToBeDeleted, refreshPolicy, updatedMonitors, listener);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            TransportIndexDetectorAction.this.handleUpsertWorkflowFailure(
                                    e, listener, detector, monitorsToBeDeleted, refreshPolicy, updatedMonitors);
                        }
                    });
        }
    }

    private IndexMonitorRequest createDocLevelMonitorRequest(
            List<Pair<String, Rule>> queries,
            List<DocLevelQuery> threatIntelQueries,
            Detector detector,
            RefreshPolicy refreshPolicy,
            String monitorId,
            Method restMethod,
            List<String> queryFieldNames) {
        List<DocLevelMonitorInput> docLevelMonitorInputs = new ArrayList<>();

        List<DocLevelQuery> docLevelQueries = new ArrayList<>();

        for (Pair<String, Rule> query : queries) {
            String id = query.getLeft();

            Rule rule = query.getRight();
            String name = rule.getMetadata().getTitle();
            String actualQuery = rule.getQueries().get(0).getValue();

            List<String> tags = new ArrayList<>();
            tags.add(rule.getLevel());
            tags.add(rule.getCategory());
            tags.addAll(rule.getTags().stream().map(Value::getValue).collect(Collectors.toList()));

            DocLevelQuery docLevelQuery =
                    new DocLevelQuery(id, name, Collections.emptyList(), actualQuery, tags, queryFieldNames);
            docLevelQueries.add(docLevelQuery);
        }
        docLevelQueries.addAll(threatIntelQueries);
        DocLevelMonitorInput docLevelMonitorInput =
                new DocLevelMonitorInput(
                        detector.getName(), detector.getInputs().get(0).getIndices(), docLevelQueries, true);
        docLevelMonitorInputs.add(docLevelMonitorInput);

        List<DocumentLevelTrigger> triggers = new ArrayList<>();
        List<DetectorTrigger> detectorTriggers = detector.getTriggers();

        for (DetectorTrigger detectorTrigger : detectorTriggers) {
            String id = detectorTrigger.getId();
            String name = detectorTrigger.getName();
            String severity = detectorTrigger.getSeverity();
            List<Action> actions = detectorTrigger.getActions();
            Script condition = detectorTrigger.convertToCondition();

            triggers.add(new DocumentLevelTrigger(id, name, severity, actions, condition));
        }

        Monitor monitor =
                new Monitor(
                        monitorId,
                        Monitor.NO_VERSION,
                        detector.getName(),
                        false,
                        detector.getSchedule(),
                        detector.getLastUpdateTime(),
                        null,
                        Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue(),
                        detector.getUser(),
                        1,
                        docLevelMonitorInputs,
                        triggers,
                        Map.of(),
                        new DataSources(
                                detector.getRuleIndex(),
                                detector.getFindingsIndex(),
                                detector.getFindingsIndexPattern(),
                                detector.getAlertsIndex(),
                                detector.getAlertsHistoryIndex(),
                                detector.getAlertsHistoryIndexPattern(),
                                DetectorMonitorConfig.getRuleIndexMappingsByType(),
                                true),
                        this.enableDetectorWithDedicatedQueryIndices,
                        null,
                        PLUGIN_OWNER_FIELD);

        return new IndexMonitorRequest(
                monitorId,
                SequenceNumbers.UNASSIGNED_SEQ_NO,
                SequenceNumbers.UNASSIGNED_PRIMARY_TERM,
                refreshPolicy,
                restMethod,
                monitor,
                null,
                true);
    }

    private void handleUpsertWorkflowFailure(
            final Exception e,
            final ActionListener<List<IndexMonitorResponse>> listener,
            final Detector detector,
            final List<String> monitorsToBeDeleted,
            final RefreshPolicy refreshPolicy,
            final List<IndexMonitorResponse> updatedMonitors) {
        if (this.exceptionChecker.doesGroupedActionListenerExceptionMatch(
                e, List.of(ThrowableCheckingPredicates.WORKFLOW_NOT_FOUND))) {
            if (detector.getEnabled()) {
                final String errorMessage =
                        String.format(
                                "Underlying workflow associated with detector %s not found. "
                                        + "Delete and recreate the detector to restore functionality.",
                                detector.getName());
                log.error(errorMessage);
                listener.onFailure(new SecurityAnalyticsException(errorMessage, RestStatus.BAD_REQUEST, e));
            } else {
                log.error(
                        "Underlying workflow associated with detector {} not found. Proceeding to disable detector.",
                        detector.getName());
                this.deleteMonitorStep(monitorsToBeDeleted, refreshPolicy, updatedMonitors, listener);
            }
        } else {
            log.error("Failed to update the workflow");
            listener.onFailure(e);
        }
    }

    private void addThreatIntelBasedDocLevelQueries(
            Detector detector, ActionListener<List<DocLevelQuery>> listener) {
        try {
            if (detector.getThreatIntelEnabled()) {
                log.debug(
                        "threat intel enabled for detector {} . adding threat intel based doc level queries.",
                        detector.getName());
                List<LogType.IocFields> iocFieldsList =
                        this.logTypeService.getIocFieldsList(detector.getDetectorType());
                if (iocFieldsList == null || iocFieldsList.isEmpty()) {
                    listener.onResponse(List.of());
                } else {
                    throw new UnsupportedOperationException("IOC stuff was removed from the plugin");
                }
            } else {
                listener.onResponse(List.of());
            }
        } catch (Exception e) {
            log.error("Failed to add threat intel based doc level queries: {}", e.getMessage());
            listener.onFailure(e);
        }
    }

    /**
     * Creates doc level monitor which generates per document alerts for the findings of the bucket
     * level delegate monitors in a workflow. This monitor has match all query applied to generate the
     * alerts per each finding doc.
     */
    private IndexMonitorRequest createDocLevelMonitorMatchAllRequest(
            Detector detector,
            RefreshPolicy refreshPolicy,
            String monitorId,
            Method restMethod,
            List<Pair<String, Rule>> queries) {
        List<DocLevelMonitorInput> docLevelMonitorInputs = new ArrayList<>();
        List<DocLevelQuery> docLevelQueries = new ArrayList<>();
        String monitorName = detector.getName() + "_chained_findings";
        String actualQuery = "_id:*";
        Set<String> tags = new HashSet<>();
        for (Pair<String, Rule> query : queries) {
            if (query.getRight().isAggregationRule()) {
                Rule rule = query.getRight();
                tags.add(rule.getLevel());
                tags.add(rule.getId());
                tags.add(rule.getCategory());
                tags.addAll(rule.getTags().stream().map(Value::getValue).collect(Collectors.toList()));
            }
        }
        tags.removeIf(Objects::isNull);

        // if queryFieldNames is not passed, alerting doc-level monitor fetches entire log doc.
        List<String> queryFieldNames = List.of("_id");
        DocLevelQuery docLevelQuery =
                new DocLevelQuery(
                        monitorName,
                        monitorName + "doc",
                        Collections.emptyList(),
                        actualQuery,
                        new ArrayList<>(tags),
                        queryFieldNames);
        docLevelQueries.add(docLevelQuery);

        DocLevelMonitorInput docLevelMonitorInput =
                new DocLevelMonitorInput(
                        detector.getName(), detector.getInputs().get(0).getIndices(), docLevelQueries, false);
        docLevelMonitorInputs.add(docLevelMonitorInput);

        List<DocumentLevelTrigger> triggers = new ArrayList<>();
        List<DetectorTrigger> detectorTriggers = detector.getTriggers();

        for (DetectorTrigger detectorTrigger : detectorTriggers) {
            String id = detectorTrigger.getId();
            String name = detectorTrigger.getName();
            String severity = detectorTrigger.getSeverity();
            List<Action> actions = detectorTrigger.getActions();
            Script condition = detectorTrigger.convertToConditionForChainedFindings();

            triggers.add(new DocumentLevelTrigger(id, name, severity, actions, condition));
        }

        Monitor monitor =
                new Monitor(
                        monitorId,
                        Monitor.NO_VERSION,
                        monitorName,
                        false,
                        detector.getSchedule(),
                        detector.getLastUpdateTime(),
                        null,
                        Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue(),
                        detector.getUser(),
                        1,
                        docLevelMonitorInputs,
                        triggers,
                        Map.of(),
                        new DataSources(
                                this.enableDetectorWithDedicatedQueryIndices
                                        ? detector.getRuleIndex() + "_chained_findings"
                                        : detector.getRuleIndex(),
                                detector.getFindingsIndex(),
                                detector.getFindingsIndexPattern(),
                                detector.getAlertsIndex(),
                                detector.getAlertsHistoryIndex(),
                                detector.getAlertsHistoryIndexPattern(),
                                DetectorMonitorConfig.getRuleIndexMappingsByType(),
                                true),
                        this.enableDetectorWithDedicatedQueryIndices,
                        true,
                        PLUGIN_OWNER_FIELD);

        return new IndexMonitorRequest(
                monitorId,
                SequenceNumbers.UNASSIGNED_SEQ_NO,
                SequenceNumbers.UNASSIGNED_PRIMARY_TERM,
                refreshPolicy,
                restMethod,
                monitor,
                null,
                true);
    }

    private void buildBucketLevelMonitorRequests(
            List<Pair<String, Rule>> queries,
            Detector detector,
            WriteRequest.RefreshPolicy refreshPolicy,
            String monitorId,
            RestRequest.Method restMethod,
            ActionListener<List<IndexMonitorRequest>> listener)
            throws Exception {
        log.debug("bucket level monitor request starting");
        log.debug("get rule field mappings request being made");
        this.logTypeService.getRuleFieldMappings(
                new ActionListener<>() {
                    @Override
                    public void onResponse(Map<String, Map<String, String>> ruleFieldMappings) {
                        log.debug("got rule field mapping success");
                        List<String> ruleCategories =
                                queries.stream()
                                        .map(Pair::getRight)
                                        .map(Rule::getCategory)
                                        .distinct()
                                        .collect(Collectors.toList());
                        Map<String, QueryBackend> queryBackendMap = new HashMap<>();
                        for (String category : ruleCategories) {
                            Map<String, String> fieldMappings = ruleFieldMappings.get(category);
                            try {
                                queryBackendMap.put(category, new OSQueryBackend(fieldMappings, true, true));
                            } catch (IOException e) {
                                TransportIndexDetectorAction.this.logger.error(
                                        "Failed to create OSQueryBackend from field mappings: {}", e.getMessage());
                                listener.onFailure(e);
                            }
                        }

                        List<IndexMonitorRequest> monitorRequests = new ArrayList<>();
                        GroupedActionListener<IndexMonitorRequest> bucketLevelMonitorRequestsListener =
                                new GroupedActionListener<>(
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(Collection<IndexMonitorRequest> indexMonitorRequests) {
                                                // if workflow usage enabled, add chained findings monitor request if there
                                                // are bucket level requests and if the detector triggers have any group by
                                                // rules configured to trigger
                                                if (TransportIndexDetectorAction.this.shouldAddChainedFindingDocMonitor(
                                                        monitorRequests.isEmpty(), queries)) {
                                                    monitorRequests.add(
                                                            TransportIndexDetectorAction.this
                                                                    .createDocLevelMonitorMatchAllRequest(
                                                                            detector,
                                                                            RefreshPolicy.IMMEDIATE,
                                                                            detector.getId() + "_chained_findings",
                                                                            Method.POST,
                                                                            queries));
                                                }
                                                listener.onResponse(monitorRequests);
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                listener.onFailure(e);
                                            }
                                        },
                                        queries.size());
                        for (Pair<String, Rule> query : queries) {
                            Rule rule = query.getRight();

                            // Creating bucket level monitor per each aggregation rule
                            if (rule.getAggregationQueries() != null) {
                                try {
                                    TransportIndexDetectorAction.this.createBucketLevelMonitorRequest(
                                            query.getRight(),
                                            detector,
                                            refreshPolicy,
                                            monitorId,
                                            restMethod,
                                            queryBackendMap.get(rule.getCategory()),
                                            new ActionListener<>() {
                                                @Override
                                                public void onResponse(IndexMonitorRequest indexMonitorRequest) {
                                                    monitorRequests.add(indexMonitorRequest);
                                                    bucketLevelMonitorRequestsListener.onResponse(indexMonitorRequest);
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    TransportIndexDetectorAction.this.logger.error(
                                                            "Failed to build bucket level monitor requests: {}", e.getMessage());
                                                    bucketLevelMonitorRequestsListener.onFailure(e);
                                                }
                                            });
                                } catch (SigmaConditionError e) {
                                    // Changed to wrap specific error instead of generic RuntimeException
                                    throw SecurityAnalyticsException.wrap(e);
                                }

                            } else {
                                log.debug("Aggregation query is null in rule {}", rule.getId());
                                bucketLevelMonitorRequestsListener.onResponse(null);
                            }
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
    }

    private void createBucketLevelMonitorRequest(
            Rule rule,
            Detector detector,
            WriteRequest.RefreshPolicy refreshPolicy,
            String monitorId,
            RestRequest.Method restMethod,
            QueryBackend queryBackend,
            ActionListener<IndexMonitorRequest> listener)
            throws SigmaConditionError {
        log.debug(":create bucket level monitor response starting");
        List<String> indices = detector.getInputs().get(0).getIndices();
        try {
            AggregationItem aggItem = rule.getAggregationItemsFromRule().get(0);
            AggregationQueries aggregationQueries = queryBackend.convertAggregation(aggItem);

            SearchSourceBuilder searchSourceBuilder =
                    new SearchSourceBuilder()
                            .seqNoAndPrimaryTerm(true)
                            .version(true)
                            // Build query string filter
                            .query(QueryBuilders.queryStringQuery(rule.getQueries().get(0).getValue()))
                            .aggregation(aggregationQueries.getAggBuilder());
            // input index can also be an index pattern or alias so we have to resolve it to concrete
            // index
            String concreteIndex =
                    IndexUtils.getNewIndexByCreationDate(
                            this.clusterService.state(),
                            this.indexNameExpressionResolver,
                            indices.get(
                                    0) // taking first one is fine because we expect that all indices in list share
                            // same mappings
                            );
            this.client.execute(
                    GetIndexMappingsAction.INSTANCE,
                    new GetIndexMappingsRequest(concreteIndex),
                    new ActionListener<GetIndexMappingsResponse>() {
                        @Override
                        public void onResponse(GetIndexMappingsResponse getIndexMappingsResponse) {
                            MappingMetadata mappingMetadata =
                                    getIndexMappingsResponse.mappings().get(concreteIndex);
                            List<Pair<String, String>> pairs = null;
                            try {
                                pairs = MapperUtils.getAllAliasPathPairs(mappingMetadata);
                            } catch (IOException e) {
                                TransportIndexDetectorAction.this.logger.debug(
                                        "Failed to get alias path pairs from mapping metadata: {}", e.getMessage());
                                this.onFailure(e);
                            }
                            boolean timeStampAliasPresent =
                                    pairs.stream()
                                            .anyMatch(
                                                    p ->
                                                            TIMESTAMP_FIELD_ALIAS.equals(p.getLeft())
                                                                    || TIMESTAMP_FIELD_ALIAS.equals(p.getRight()));
                            if (timeStampAliasPresent) {
                                BoolQueryBuilder boolQueryBuilder =
                                        searchSourceBuilder.query() == null
                                                ? new BoolQueryBuilder()
                                                : QueryBuilders.boolQuery().must(searchSourceBuilder.query());
                                RangeQueryBuilder timeRangeFilter =
                                        QueryBuilders.rangeQuery(TIMESTAMP_FIELD_ALIAS)
                                                .gt(
                                                        "{{period_end}}||-"
                                                                + (aggItem.getTimeframe() != null ? aggItem.getTimeframe() : "1h"))
                                                .lte("{{period_end}}")
                                                .format("epoch_millis");
                                boolQueryBuilder.must(timeRangeFilter);
                                searchSourceBuilder.query(boolQueryBuilder);
                            }
                            // query hits are not needed from this query part for aggregations.
                            searchSourceBuilder.size(0);
                            List<SearchInput> bucketLevelMonitorInputs = new ArrayList<>();
                            bucketLevelMonitorInputs.add(new SearchInput(indices, searchSourceBuilder));

                            List<BucketLevelTrigger> triggers = new ArrayList<>();
                            BucketLevelTrigger bucketLevelTrigger =
                                    new BucketLevelTrigger(
                                            rule.getId(),
                                            rule.getMetadata().getTitle(),
                                            rule.getLevel(),
                                            aggregationQueries.getCondition(),
                                            Collections.emptyList());
                            triggers.add(bucketLevelTrigger);

                            /**
                             * TODO - Think how to use detector trigger List<DetectorTrigger> detectorTriggers =
                             * detector.getTriggers(); for (DetectorTrigger detectorTrigger: detectorTriggers) {
                             * String id = detectorTrigger.getId(); String name = detectorTrigger.getName();
                             * String severity = detectorTrigger.getSeverity(); List<Action> actions =
                             * detectorTrigger.getActions(); Script condition =
                             * detectorTrigger.convertToCondition();
                             *
                             * <p>BucketLevelTrigger bucketLevelTrigger1 = new BucketLevelTrigger(id, name,
                             * severity, condition, actions); triggers.add(bucketLevelTrigger1); } *
                             */
                            Monitor monitor =
                                    new Monitor(
                                            monitorId,
                                            Monitor.NO_VERSION,
                                            detector.getName(),
                                            false,
                                            detector.getSchedule(),
                                            detector.getLastUpdateTime(),
                                            null,
                                            MonitorType.BUCKET_LEVEL_MONITOR.getValue(),
                                            detector.getUser(),
                                            1,
                                            bucketLevelMonitorInputs,
                                            triggers,
                                            Map.of(),
                                            new DataSources(
                                                    detector.getRuleIndex(),
                                                    detector.getFindingsIndex(),
                                                    detector.getFindingsIndexPattern(),
                                                    detector.getAlertsIndex(),
                                                    detector.getAlertsHistoryIndex(),
                                                    detector.getAlertsHistoryIndexPattern(),
                                                    DetectorMonitorConfig.getRuleIndexMappingsByType(),
                                                    true),
                                            false,
                                            null,
                                            PLUGIN_OWNER_FIELD);

                            listener.onResponse(
                                    new IndexMonitorRequest(
                                            monitorId,
                                            SequenceNumbers.UNASSIGNED_SEQ_NO,
                                            SequenceNumbers.UNASSIGNED_PRIMARY_TERM,
                                            refreshPolicy,
                                            restMethod,
                                            monitor,
                                            null,
                                            true));
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error(
                                    String.format(
                                            Locale.getDefault(),
                                            "Unable to verify presence of timestamp alias for index [%s] in detector [%s]. Not setting time range filter for bucket level monitor. Error: %s",
                                            concreteIndex,
                                            detector.getName(),
                                            e.getMessage()),
                                    e);
                            listener.onFailure(e);
                        }
                    });
        } catch (Exception e) {
            log.error("Failed to create bucket level monitor request: {}", e.getMessage());
            listener.onFailure(e);
        }
    }

    /**
     * Executes monitor related requests (PUT/POST) - returns the response once all the executions are
     * completed
     *
     * @param indexMonitors Monitors to be updated/added
     * @param listener actionListener for handling updating/creating monitors
     */
    public void executeMonitorActionRequest(
            List<IndexMonitorRequest> indexMonitors,
            ActionListener<List<IndexMonitorResponse>> listener) {

        // In the case of not provided monitors, just return empty list
        if (indexMonitors == null || indexMonitors.isEmpty()) {
            listener.onResponse(new ArrayList<>());
            return;
        }

        GroupedActionListener<IndexMonitorResponse> monitorResponseListener =
                new GroupedActionListener(
                        new ActionListener<Collection<IndexMonitorResponse>>() {
                            @Override
                            public void onResponse(Collection<IndexMonitorResponse> indexMonitorResponse) {
                                listener.onResponse(indexMonitorResponse.stream().collect(Collectors.toList()));
                            }

                            @Override
                            public void onFailure(Exception e) {
                                listener.onFailure(e);
                            }
                        },
                        indexMonitors.size());

        // Persist monitors sequentially
        for (IndexMonitorRequest req : indexMonitors) {
            AlertingPluginInterface.INSTANCE.indexMonitor(
                    (NodeClient) this.client, req, this.namedWriteableRegistry, monitorResponseListener);
        }
    }

    private void onCreateMappingsResponse(CreateIndexResponse response) throws Exception {
        if (response.isAcknowledged()) {
            log.info(
                    String.format(
                            Locale.getDefault(), "Created %s with mappings.", Detector.DETECTORS_INDEX));
            IndexUtils.detectorIndexUpdated();
        } else {
            log.error(
                    String.format(
                            Locale.getDefault(),
                            "Create %s mappings call not acknowledged.",
                            Detector.DETECTORS_INDEX));
            throw new OpenSearchStatusException(
                    String.format(
                            Locale.getDefault(),
                            "Create %s mappings call not acknowledged",
                            Detector.DETECTORS_INDEX),
                    RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private void onUpdateMappingsResponse(AcknowledgedResponse response) {
        if (response.isAcknowledged()) {
            log.info(
                    String.format(
                            Locale.getDefault(), "Updated  %s with mappings.", Detector.DETECTORS_INDEX));
            IndexUtils.detectorIndexUpdated();
        } else {
            log.error(
                    String.format(
                            Locale.getDefault(),
                            "Update %s mappings call not acknowledged.",
                            Detector.DETECTORS_INDEX));
            throw new OpenSearchStatusException(
                    String.format(
                            Locale.getDefault(),
                            "Update %s mappings call not acknowledged.",
                            Detector.DETECTORS_INDEX),
                    RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    class AsyncIndexDetectorsAction {
        private final IndexDetectorRequest request;

        private final ActionListener<IndexDetectorResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;
        private final User user;

        AsyncIndexDetectorsAction(
                User user,
                Task task,
                IndexDetectorRequest request,
                ActionListener<IndexDetectorResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;
            this.user = user;

            this.response = new AtomicReference<>();
        }

        void start() {
            log.debug("stash context");
            TransportIndexDetectorAction.this.threadPool.getThreadContext().stashContext();
            log.debug("log type check : {}", this.request.getDetector().getDetectorType());
            TransportIndexDetectorAction.this.logTypeService.doesLogTypeExist(
                    this.request.getDetector().getDetectorType().toLowerCase(Locale.ROOT),
                    new ActionListener<>() {
                        @Override
                        public void onResponse(Boolean exist) {
                            if (exist) {
                                log.debug(
                                        "log type exists : {}",
                                        AsyncIndexDetectorsAction.this.request.getDetector().getDetectorType());
                                try {
                                    if (!TransportIndexDetectorAction.this.detectorIndices.detectorIndexExists()) {
                                        log.debug("detector index creation");
                                        TransportIndexDetectorAction.this.detectorIndices.initDetectorIndex(
                                                new ActionListener<>() {
                                                    @Override
                                                    public void onResponse(CreateIndexResponse response) {
                                                        try {
                                                            log.debug("detector index created in {}");

                                                            TransportIndexDetectorAction.this.onCreateMappingsResponse(response);
                                                            AsyncIndexDetectorsAction.this.prepareDetectorIndexing();
                                                        } catch (Exception e) {
                                                            log.debug("detector index creation failed", e);
                                                            AsyncIndexDetectorsAction.this.onFailures(e);
                                                        }
                                                    }

                                                    @Override
                                                    public void onFailure(Exception e) {
                                                        AsyncIndexDetectorsAction.this.onFailures(e);
                                                    }
                                                });
                                    } else if (!IndexUtils.detectorIndexUpdated) {
                                        log.debug("detector index update mapping");
                                        IndexUtils.updateIndexMapping(
                                                Detector.DETECTORS_INDEX,
                                                DetectorIndices.detectorMappings(),
                                                TransportIndexDetectorAction.this.clusterService.state(),
                                                TransportIndexDetectorAction.this.client.admin().indices(),
                                                new ActionListener<>() {
                                                    @Override
                                                    public void onResponse(AcknowledgedResponse response) {
                                                        log.debug("detector index mapping updated");
                                                        TransportIndexDetectorAction.this.onUpdateMappingsResponse(response);
                                                        try {
                                                            AsyncIndexDetectorsAction.this.prepareDetectorIndexing();
                                                        } catch (Exception e) {
                                                            log.debug("detector index mapping FAILED updation", e);
                                                            AsyncIndexDetectorsAction.this.onFailures(e);
                                                        }
                                                    }

                                                    @Override
                                                    public void onFailure(Exception e) {
                                                        AsyncIndexDetectorsAction.this.onFailures(e);
                                                    }
                                                },
                                                false);
                                    } else {
                                        AsyncIndexDetectorsAction.this.prepareDetectorIndexing();
                                    }
                                } catch (Exception e) {
                                    AsyncIndexDetectorsAction.this.onFailures(e);
                                }
                            } else {
                                AsyncIndexDetectorsAction.this.onFailures(
                                        new OpenSearchStatusException(
                                                String.format(
                                                        "Detector cannot be created as logtype %s does not exist",
                                                        AsyncIndexDetectorsAction.this
                                                                .request
                                                                .getDetector()
                                                                .getDetectorType()
                                                                .toLowerCase(Locale.ROOT)),
                                                RestStatus.BAD_REQUEST));
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {}
                    });
        }

        void prepareDetectorIndexing() throws Exception {
            if (this.request.getMethod() == RestRequest.Method.POST) {
                this.createDetector();
            } else if (this.request.getMethod() == RestRequest.Method.PUT) {
                this.updateDetector();
            }
        }

        void createDetector() {
            Detector detector = this.request.getDetector();
            String ruleTopic = detector.getDetectorType();

            this.request.getDetector().setAlertsIndex(DetectorMonitorConfig.getAlertsIndex(ruleTopic));
            this.request
                    .getDetector()
                    .setAlertsHistoryIndex(DetectorMonitorConfig.getAlertsHistoryIndex(ruleTopic));
            this.request
                    .getDetector()
                    .setAlertsHistoryIndexPattern(
                            DetectorMonitorConfig.getAlertsHistoryIndexPattern(ruleTopic));
            this.request
                    .getDetector()
                    .setFindingsIndex(DetectorMonitorConfig.getFindingsIndex(ruleTopic));
            this.request
                    .getDetector()
                    .setFindingsIndexPattern(DetectorMonitorConfig.getFindingsIndexPattern(ruleTopic));

            if (TransportIndexDetectorAction.this.enableDetectorWithDedicatedQueryIndices) {
                // disabling the setting after enabling it will mean delete & re-create the detector
                this.request
                        .getDetector()
                        .setRuleIndex(DetectorMonitorConfig.getRuleIndexOptimized(ruleTopic));
            } else {
                this.request.getDetector().setRuleIndex(DetectorMonitorConfig.getRuleIndex(ruleTopic));
            }

            User originalContextUser = this.user;
            log.debug("user from original context is {}", originalContextUser);
            this.request.getDetector().setUser(originalContextUser);

            if (!detector.getInputs().isEmpty()) {
                try {
                    String spaceError = TransportIndexDetectorAction.validateSingleRuleSpace(detector);
                    if (spaceError != null) {
                        this.onFailures(new OpenSearchStatusException(spaceError, RestStatus.BAD_REQUEST));
                        return;
                    }
                    log.debug("init rule index template");
                    TransportIndexDetectorAction.this.ruleTopicIndices.initRuleTopicIndexTemplate(
                            new ActionListener<>() {
                                @Override
                                public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                                    log.debug("init rule index template ack");
                                    AsyncIndexDetectorsAction.this.initRuleIndexAndImportRules(
                                            AsyncIndexDetectorsAction.this.request,
                                            new ActionListener<>() {
                                                @Override
                                                public void onResponse(List<IndexMonitorResponse> monitorResponses) {
                                                    log.debug("monitors indexed");
                                                    AsyncIndexDetectorsAction.this
                                                            .request
                                                            .getDetector()
                                                            .setMonitorIds(
                                                                    AsyncIndexDetectorsAction.this.getMonitorIds(monitorResponses));
                                                    AsyncIndexDetectorsAction.this
                                                            .request
                                                            .getDetector()
                                                            .setRuleIdMonitorIdMap(
                                                                    AsyncIndexDetectorsAction.this.mapMonitorIds(monitorResponses));
                                                    try {
                                                        AsyncIndexDetectorsAction.this.indexDetector();
                                                    } catch (Exception e) {
                                                        TransportIndexDetectorAction.this.logger.debug(
                                                                "create detector failed", e);
                                                        AsyncIndexDetectorsAction.this.onFailures(e);
                                                    }
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    TransportIndexDetectorAction.this.logger.debug("import rules failed", e);
                                                    AsyncIndexDetectorsAction.this.onFailures(e);
                                                }
                                            });
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    TransportIndexDetectorAction.this.logger.debug("init rules index failed", e);
                                    AsyncIndexDetectorsAction.this.onFailures(e);
                                }
                            });
                } catch (Exception e) {
                    TransportIndexDetectorAction.this.logger.debug("init rules index failed", e);
                    this.onFailures(e);
                }
            }
        }

        void updateDetector() {
            String id = this.request.getDetectorId();

            User originalContextUser = this.user;
            log.debug("user from original context is {}", originalContextUser);

            GetRequest request = new GetRequest(Detector.DETECTORS_INDEX, id);
            TransportIndexDetectorAction.this.client.get(
                    request,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(GetResponse response) {
                            if (!response.isExists()) {
                                AsyncIndexDetectorsAction.this.createDetector();
                                return;
                            }

                            try {
                                XContentParser xcp =
                                        XContentHelper.createParser(
                                                TransportIndexDetectorAction.this.xContentRegistry,
                                                LoggingDeprecationHandler.INSTANCE,
                                                response.getSourceAsBytesRef(),
                                                XContentType.JSON);

                                Detector detector = Detector.docParse(xcp, response.getId(), response.getVersion());

                                // security is enabled and filterby is enabled
                                if (!TransportIndexDetectorAction.this.checkUserPermissionsWithResource(
                                        originalContextUser,
                                        detector.getUser(),
                                        "detector",
                                        detector.getId(),
                                        TransportIndexDetectorAction.this.filterByEnabled)) {

                                    this.onFailure(
                                            SecurityAnalyticsException.wrap(
                                                    new OpenSearchStatusException(
                                                            "Do not have permissions to resource", RestStatus.FORBIDDEN)));
                                    return;
                                }
                                AsyncIndexDetectorsAction.this.onGetResponse(detector, detector.getUser());
                            } catch (Exception e) {
                                AsyncIndexDetectorsAction.this.onFailures(e);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            AsyncIndexDetectorsAction.this.onFailures(e);
                        }
                    });
        }

        void onGetResponse(Detector currentDetector, User user) {
            if (this.request.getDetector().getEnabled() && currentDetector.getEnabled()) {
                this.request.getDetector().setEnabledTime(currentDetector.getEnabledTime());
            }
            this.request.getDetector().setMonitorIds(currentDetector.getMonitorIds());
            this.request.getDetector().setRuleIdMonitorIdMap(currentDetector.getRuleIdMonitorIdMap());
            this.request.getDetector().setWorkflowIds(currentDetector.getWorkflowIds());
            Detector detector = this.request.getDetector();

            String ruleTopic = detector.getDetectorType();

            log.debug("user in update detector {}", user);

            this.request.getDetector().setAlertsIndex(DetectorMonitorConfig.getAlertsIndex(ruleTopic));
            this.request
                    .getDetector()
                    .setAlertsHistoryIndex(DetectorMonitorConfig.getAlertsHistoryIndex(ruleTopic));
            this.request
                    .getDetector()
                    .setAlertsHistoryIndexPattern(
                            DetectorMonitorConfig.getAlertsHistoryIndexPattern(ruleTopic));
            this.request
                    .getDetector()
                    .setFindingsIndex(DetectorMonitorConfig.getFindingsIndex(ruleTopic));
            this.request
                    .getDetector()
                    .setFindingsIndexPattern(DetectorMonitorConfig.getFindingsIndexPattern(ruleTopic));
            if (currentDetector.getRuleIndex().contains("optimized")) {
                this.request.getDetector().setRuleIndex(currentDetector.getRuleIndex());
            } else {
                if (TransportIndexDetectorAction.this.enableDetectorWithDedicatedQueryIndices) {
                    // disabling the setting after enabling it will mean delete & re-create the detector
                    this.request
                            .getDetector()
                            .setRuleIndex(DetectorMonitorConfig.getRuleIndexOptimized(ruleTopic));
                } else {
                    this.request.getDetector().setRuleIndex(DetectorMonitorConfig.getRuleIndex(ruleTopic));
                }
            }
            this.request.getDetector().setUser(user);

            if (!detector.getInputs().isEmpty()) {
                try {
                    String spaceError = TransportIndexDetectorAction.validateSingleRuleSpace(detector);
                    if (spaceError != null) {
                        this.onFailures(new OpenSearchStatusException(spaceError, RestStatus.BAD_REQUEST));
                        return;
                    }
                    TransportIndexDetectorAction.this.ruleTopicIndices.initRuleTopicIndexTemplate(
                            new ActionListener<>() {
                                @Override
                                public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                                    AsyncIndexDetectorsAction.this.initRuleIndexAndImportRules(
                                            AsyncIndexDetectorsAction.this.request,
                                            new ActionListener<>() {
                                                @Override
                                                public void onResponse(List<IndexMonitorResponse> monitorResponses) {
                                                    AsyncIndexDetectorsAction.this
                                                            .request
                                                            .getDetector()
                                                            .setMonitorIds(
                                                                    AsyncIndexDetectorsAction.this.getMonitorIds(monitorResponses));
                                                    AsyncIndexDetectorsAction.this
                                                            .request
                                                            .getDetector()
                                                            .setRuleIdMonitorIdMap(
                                                                    AsyncIndexDetectorsAction.this.mapMonitorIds(monitorResponses));
                                                    try {
                                                        AsyncIndexDetectorsAction.this.indexDetector();
                                                    } catch (Exception e) {
                                                        AsyncIndexDetectorsAction.this.onFailures(e);
                                                    }
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    AsyncIndexDetectorsAction.this.onFailures(e);
                                                }
                                            });
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    AsyncIndexDetectorsAction.this.onFailures(e);
                                }
                            });
                } catch (Exception e) {
                    this.onFailures(e);
                }
            }
        }

        public void initRuleIndexAndImportRules(
                IndexDetectorRequest request, ActionListener<List<IndexMonitorResponse>> listener) {
            // Disabled pre-packaged rules reimport for production builds, enabled only on test
            // environments.
            // Issue: https://github.com/wazuh/internal-devel-requests/issues/3587
            String enabledPrepackaged = System.getProperty("default_rules.enabled");

            if (enabledPrepackaged != null && enabledPrepackaged.equals("true")) {
                // Original behavior: delete and reimport rules from filesystem
                TransportIndexDetectorAction.this.ruleIndices.initPrepackagedRulesIndex(
                        new ActionListener<>() {
                            @Override
                            public void onResponse(CreateIndexResponse response) {
                                log.debug("prepackaged rule index created");
                                TransportIndexDetectorAction.this.ruleIndices.onCreateMappingsResponse(
                                        response, true);
                                TransportIndexDetectorAction.this.ruleIndices.importRules(
                                        RefreshPolicy.IMMEDIATE,
                                        TransportIndexDetectorAction.this.indexTimeout,
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(BulkResponse response) {
                                                log.debug("rules imported");
                                                if (!response.hasFailures()) {
                                                    AsyncIndexDetectorsAction.this.importRules(request, listener);
                                                } else {
                                                    AsyncIndexDetectorsAction.this.onFailures(
                                                            new OpenSearchStatusException(
                                                                    response.buildFailureMessage(),
                                                                    RestStatus.INTERNAL_SERVER_ERROR));
                                                }
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                log.debug("failed to import rules", e);
                                                AsyncIndexDetectorsAction.this.onFailures(e);
                                            }
                                        });
                            }

                            @Override
                            public void onFailure(Exception e) {
                                AsyncIndexDetectorsAction.this.onFailures(e);
                            }
                        },
                        new ActionListener<>() {
                            @Override
                            public void onResponse(AcknowledgedResponse response) {
                                TransportIndexDetectorAction.this.ruleIndices.onUpdateMappingsResponse(
                                        response, true);
                                TransportIndexDetectorAction.this.ruleIndices.deleteRules(
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(BulkByScrollResponse response) {
                                                TransportIndexDetectorAction.this.ruleIndices.importRules(
                                                        WriteRequest.RefreshPolicy.IMMEDIATE,
                                                        TransportIndexDetectorAction.this.indexTimeout,
                                                        new ActionListener<>() {
                                                            @Override
                                                            public void onResponse(BulkResponse response) {
                                                                if (!response.hasFailures()) {
                                                                    AsyncIndexDetectorsAction.this.importRules(request, listener);
                                                                } else {
                                                                    AsyncIndexDetectorsAction.this.onFailures(
                                                                            new OpenSearchStatusException(
                                                                                    response.buildFailureMessage(),
                                                                                    RestStatus.INTERNAL_SERVER_ERROR));
                                                                }
                                                            }

                                                            @Override
                                                            public void onFailure(Exception e) {
                                                                AsyncIndexDetectorsAction.this.onFailures(e);
                                                            }
                                                        });
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                AsyncIndexDetectorsAction.this.onFailures(e);
                                            }
                                        });
                            }

                            @Override
                            public void onFailure(Exception e) {
                                AsyncIndexDetectorsAction.this.onFailures(e);
                            }
                        },
                        new ActionListener<>() {
                            @Override
                            public void onResponse(SearchResponse response) {
                                if (response.isTimedOut()) {
                                    AsyncIndexDetectorsAction.this.onFailures(
                                            new OpenSearchStatusException(
                                                    "Search request timed out", RestStatus.REQUEST_TIMEOUT));
                                }

                                long count = response.getHits().getTotalHits().value();
                                if (count == 0) {
                                    TransportIndexDetectorAction.this.ruleIndices.importRules(
                                            WriteRequest.RefreshPolicy.IMMEDIATE,
                                            TransportIndexDetectorAction.this.indexTimeout,
                                            new ActionListener<>() {
                                                @Override
                                                public void onResponse(BulkResponse response) {
                                                    if (!response.hasFailures()) {
                                                        AsyncIndexDetectorsAction.this.importRules(request, listener);
                                                    } else {
                                                        AsyncIndexDetectorsAction.this.onFailures(
                                                                new OpenSearchStatusException(
                                                                        response.buildFailureMessage(),
                                                                        RestStatus.INTERNAL_SERVER_ERROR));
                                                    }
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    AsyncIndexDetectorsAction.this.onFailures(e);
                                                }
                                            });
                                } else {
                                    AsyncIndexDetectorsAction.this.importRules(request, listener);
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                AsyncIndexDetectorsAction.this.onFailures(e);
                            }
                        });
            } else {
                // Production: Don't delete/reimport rules, just use existing rules from index
                // Rules are synced externally via CatalogSyncJob's WTransportIndexRuleAction
                this.importRules(request, listener);
            }
        }

        @SuppressWarnings("unchecked")
        public void importRules(
                IndexDetectorRequest request, ActionListener<List<IndexMonitorResponse>> listener) {
            final Detector detector = request.getDetector();
            final String ruleTopic = detector.getDetectorType();
            final DetectorInput detectorInput = detector.getInputs().get(0);
            final String logIndex = detectorInput.getIndices().get(0);

            String spaceError = TransportIndexDetectorAction.validateSingleRuleSpace(detector);
            if (spaceError != null) {
                this.onFailures(new OpenSearchStatusException(spaceError, RestStatus.BAD_REQUEST));
                return;
            }

            List<String> ruleIds =
                    detectorInput.getPrePackagedRules().stream()
                            .map(DetectorRule::getId)
                            .collect(Collectors.toList());

            QueryBuilder queryBuilder =
                    QueryBuilders.boolQuery()
                            .must(QueryBuilders.matchQuery("rule.category", ruleTopic))
                            .must(QueryBuilders.termsQuery("_id", ruleIds.toArray(new String[] {})));

            SearchRequest searchRequest =
                    new SearchRequest(Rule.PRE_PACKAGED_RULES_INDEX)
                            .source(
                                    new SearchSourceBuilder()
                                            .seqNoAndPrimaryTerm(true)
                                            .version(true)
                                            .query(queryBuilder)
                                            .size(10000))
                            .preference(Preference.PRIMARY_FIRST.type());
            TransportIndexDetectorAction.this.logger.debug("importing prepackaged rules");
            TransportIndexDetectorAction.this.client.search(
                    searchRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(SearchResponse response) {
                            if (response.isTimedOut()) {
                                AsyncIndexDetectorsAction.this.onFailures(
                                        new OpenSearchStatusException(
                                                "Search request timed out", RestStatus.REQUEST_TIMEOUT));
                            }
                            TransportIndexDetectorAction.this.logger.debug("prepackaged rules fetch success");

                            SearchHits hits = response.getHits();
                            List<Pair<String, Rule>> queries = new ArrayList<>();

                            try {
                                for (SearchHit hit : hits) {
                                    XContentParser xcp =
                                            XContentType.JSON
                                                    .xContent()
                                                    .createParser(
                                                            TransportIndexDetectorAction.this.xContentRegistry,
                                                            LoggingDeprecationHandler.INSTANCE,
                                                            hit.getSourceAsString());

                                    Rule rule = Rule.docParse(xcp, hit.getId(), hit.getVersion());
                                    String id = hit.getId();

                                    queries.add(Pair.of(id, rule));
                                }

                                if (TransportIndexDetectorAction.this.ruleIndices.ruleIndexExists(false)) {
                                    AsyncIndexDetectorsAction.this.importCustomRules(
                                            detector, detectorInput, queries, listener);
                                } else if (detectorInput.getCustomRules().size() > 0) {
                                    AsyncIndexDetectorsAction.this.onFailures(
                                            new OpenSearchStatusException(
                                                    "Custom Rule Index not found", RestStatus.NOT_FOUND));
                                } else {
                                    AsyncIndexDetectorsAction.this.resolveRuleFieldNamesAndUpsertMonitorFromQueries(
                                            queries, detector, logIndex, listener);
                                }
                            } catch (Exception e) {
                                TransportIndexDetectorAction.this.logger.debug(
                                        "failed to fetch prepackaged rules", e);
                                AsyncIndexDetectorsAction.this.onFailures(e);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            AsyncIndexDetectorsAction.this.onFailures(e);
                        }
                    });
        }

        private void resolveRuleFieldNamesAndUpsertMonitorFromQueries(
                List<Pair<String, Rule>> queries,
                Detector detector,
                String logIndex,
                ActionListener<List<IndexMonitorResponse>> listener) {
            TransportIndexDetectorAction.this.logger.debug(
                    "PERF_DEBUG_SAP: Fetching alias path pairs to construct rule_field_names");
            long start = System.currentTimeMillis();
            // Exclude rules explicitly disabled (enabled:false in their content) before compiling
            // them into the detector's Monitor. This is the single point where pre-packaged and
            // custom rules converge, so it covers every detector create/update path. See issue #1394.
            final List<Pair<String, Rule>> enabledQueries = filterEnabledRules(queries);
            Set<String> ruleFieldNames = new HashSet<>();
            for (Pair<String, Rule> query : enabledQueries) {
                List<String> queryFieldNames =
                        query.getValue().getQueryFieldNames().stream()
                                .map(Value::getValue)
                                .collect(Collectors.toList());
                ruleFieldNames.addAll(queryFieldNames);
            }
            TransportIndexDetectorAction.this.client.execute(
                    GetIndexMappingsAction.INSTANCE,
                    new GetIndexMappingsRequest(logIndex),
                    new ActionListener<>() {
                        @Override
                        public void onResponse(GetIndexMappingsResponse getMappingsViewResponse) {
                            try {
                                List<Pair<String, String>> aliasPathPairs;

                                aliasPathPairs =
                                        MapperUtils.getAllAliasPathPairs(
                                                getMappingsViewResponse.getMappings().get(logIndex));
                                for (Pair<String, String> aliasPathPair : aliasPathPairs) {
                                    if (ruleFieldNames.contains(aliasPathPair.getLeft())) {
                                        ruleFieldNames.remove(aliasPathPair.getLeft());
                                        ruleFieldNames.add(aliasPathPair.getRight());
                                    }
                                }
                                long took = System.currentTimeMillis() - start;
                                log.debug("completed collecting rule_field_names in {} millis", took);

                            } catch (Exception e) {
                                TransportIndexDetectorAction.this.logger.error(
                                        "Failure in parsing rule field names/aliases while " + detector.getId() == null
                                                ? "creating"
                                                : "updating"
                                                        + " detector. Not optimizing detector queries with relevant fields",
                                        e);
                                ruleFieldNames.clear();
                            }
                            AsyncIndexDetectorsAction.this.upsertMonitorQueries(
                                    enabledQueries, detector, listener, ruleFieldNames, logIndex);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to fetch mappings view response for log index " + logIndex, e);
                            listener.onFailure(e);
                        }
                    });
        }

        private void upsertMonitorQueries(
                List<Pair<String, Rule>> queries,
                Detector detector,
                ActionListener<List<IndexMonitorResponse>> listener,
                Set<String> ruleFieldNames,
                String logIndex) {
            if (this.request.getMethod() == Method.POST || detector.getMonitorIds().isEmpty()) {
                TransportIndexDetectorAction.this.createMonitorFromQueries(
                        queries,
                        detector,
                        listener,
                        this.request.getRefreshPolicy(),
                        new ArrayList<>(ruleFieldNames));
            } else if (this.request.getMethod() == Method.PUT) {
                TransportIndexDetectorAction.this.updateMonitorFromQueries(
                        logIndex,
                        queries,
                        detector,
                        listener,
                        this.request.getRefreshPolicy(),
                        new ArrayList<>(ruleFieldNames));
            }
        }

        @SuppressWarnings("unchecked")
        public void importCustomRules(
                Detector detector,
                DetectorInput detectorInput,
                List<Pair<String, Rule>> queries,
                ActionListener<List<IndexMonitorResponse>> listener) {
            final String logIndex = detectorInput.getIndices().get(0);
            List<String> ruleIds =
                    detectorInput.getCustomRules().stream()
                            .map(DetectorRule::getId)
                            .collect(Collectors.toList());

            // Rules are identified by document.id (from the content manager) + space=custom.
            // Querying by _id would fail because the IDs received here are document.id values,
            // not the internal _id of the custom rules index.
            QueryBuilder queryBuilder =
                    QueryBuilders.boolQuery()
                            .filter(
                                    QueryBuilders.termsQuery("rule.document.id", ruleIds.toArray(new String[] {})))
                            .filter(QueryBuilders.termQuery("rule.space", "custom"));
            SearchRequest searchRequest =
                    new SearchRequest(Rule.CUSTOM_RULES_INDEX)
                            .source(
                                    new SearchSourceBuilder()
                                            .seqNoAndPrimaryTerm(true)
                                            .version(true)
                                            .query(queryBuilder)
                                            .size(10000))
                            .preference(Preference.PRIMARY_FIRST.type());
            TransportIndexDetectorAction.this.logger.debug(
                    "importing custom rules by document.id with space=custom");
            TransportIndexDetectorAction.this.client.search(
                    searchRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(SearchResponse response) {
                            if (response.isTimedOut()) {
                                AsyncIndexDetectorsAction.this.onFailures(
                                        new OpenSearchStatusException(
                                                "Search request timed out", RestStatus.REQUEST_TIMEOUT));
                            }
                            TransportIndexDetectorAction.this.logger.debug("custom rules fetch successful");
                            SearchHits hits = response.getHits();

                            if (hits.getHits().length == 0 && !ruleIds.isEmpty()) {
                                AsyncIndexDetectorsAction.this.onFailures(
                                        new OpenSearchStatusException(
                                                String.format(
                                                        "Detector creation failed. No custom rules found for IDs: %s. Ensure these rules are promoted to the 'custom' space first.",
                                                        ruleIds),
                                                RestStatus.BAD_REQUEST));
                                return;
                            }

                            try {
                                for (SearchHit hit : hits) {
                                    XContentParser xcp =
                                            XContentType.JSON
                                                    .xContent()
                                                    .createParser(
                                                            TransportIndexDetectorAction.this.xContentRegistry,
                                                            LoggingDeprecationHandler.INSTANCE,
                                                            hit.getSourceAsString());

                                    Rule rule = Rule.docParse(xcp, hit.getId(), hit.getVersion());
                                    String id = hit.getId();

                                    queries.add(Pair.of(id, rule));
                                }

                                AsyncIndexDetectorsAction.this.resolveRuleFieldNamesAndUpsertMonitorFromQueries(
                                        queries, detector, logIndex, listener);
                            } catch (Exception ex) {
                                AsyncIndexDetectorsAction.this.onFailures(ex);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            AsyncIndexDetectorsAction.this.onFailures(e);
                        }
                    });
        }

        public void indexDetector() throws Exception {
            IndexRequest indexRequest;
            if (this.request.getMethod() == RestRequest.Method.POST) {
                indexRequest =
                        new IndexRequest(Detector.DETECTORS_INDEX)
                                .setRefreshPolicy(this.request.getRefreshPolicy())
                                .source(
                                        this.request
                                                .getDetector()
                                                .toXContentWithUser(
                                                        XContentFactory.jsonBuilder(),
                                                        new ToXContent.MapParams(Map.of("with_type", "true"))))
                                .timeout(TransportIndexDetectorAction.this.indexTimeout);
            } else {
                this.request.getDetector().setLastUpdateTime(Instant.now());
                indexRequest =
                        new IndexRequest(Detector.DETECTORS_INDEX)
                                .setRefreshPolicy(this.request.getRefreshPolicy())
                                .source(
                                        this.request
                                                .getDetector()
                                                .toXContentWithUser(
                                                        XContentFactory.jsonBuilder(),
                                                        new ToXContent.MapParams(Map.of("with_type", "true"))))
                                .id(this.request.getDetectorId())
                                .timeout(TransportIndexDetectorAction.this.indexTimeout);
            }
            log.debug("indexing detector");
            TransportIndexDetectorAction.this.client.index(
                    indexRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(IndexResponse response) {
                            log.debug("detector indexed success.");
                            Detector responseDetector = AsyncIndexDetectorsAction.this.request.getDetector();
                            responseDetector.setId(response.getId());
                            AsyncIndexDetectorsAction.this.onOperation(response, responseDetector);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            // Revert the workflow and monitors created in previous steps
                            TransportIndexDetectorAction.this.workflowService.deleteWorkflow(
                                    AsyncIndexDetectorsAction.this.request.getDetector().getWorkflowIds().get(0),
                                    new ActionListener<>() {
                                        @Override
                                        public void onResponse(DeleteWorkflowResponse deleteWorkflowResponse) {
                                            TransportIndexDetectorAction.this.monitorService.deleteAlertingMonitors(
                                                    AsyncIndexDetectorsAction.this.request.getDetector().getMonitorIds(),
                                                    AsyncIndexDetectorsAction.this.request.getRefreshPolicy(),
                                                    new ActionListener<>() {
                                                        @Override
                                                        public void onResponse(
                                                                List<DeleteMonitorResponse> deleteMonitorResponses) {
                                                            AsyncIndexDetectorsAction.this.onFailures(e);
                                                        }

                                                        @Override
                                                        public void onFailure(Exception e) {
                                                            AsyncIndexDetectorsAction.this.onFailures(e);
                                                        }
                                                    });
                                        }

                                        @Override
                                        public void onFailure(Exception e) {
                                            AsyncIndexDetectorsAction.this.onFailures(e);
                                        }
                                    });
                        }
                    });
        }

        private void onOperation(IndexResponse response, Detector detector) {
            this.response.set(response);
            if (this.counter.compareAndSet(false, true)) {
                this.finishHim(detector, null);
            }
        }

        private void onFailures(Exception t) {
            if (this.counter.compareAndSet(false, true)) {
                this.finishHim(null, t);
            }
        }

        private void finishHim(Detector detector, Exception t) {
            TransportIndexDetectorAction.this
                    .threadPool
                    .executor(ThreadPool.Names.GENERIC)
                    .execute(
                            ActionRunnable.supply(
                                    this.listener,
                                    () -> {
                                        if (t != null) {
                                            log.error("exception: {}", t.getMessage());
                                            if (t instanceof OpenSearchStatusException) {
                                                throw t;
                                            }
                                            throw SecurityAnalyticsException.wrap(t);
                                        } else {
                                            return new IndexDetectorResponse(
                                                    detector.getId(),
                                                    detector.getVersion(),
                                                    this.request.getMethod() == RestRequest.Method.POST
                                                            ? RestStatus.CREATED
                                                            : RestStatus.OK,
                                                    detector);
                                        }
                                    }));
        }

        private List<String> getMonitorIds(List<IndexMonitorResponse> monitorResponses) {
            return monitorResponses.stream()
                    .map(IndexMonitorResponse::getId)
                    .collect(Collectors.toList());
        }

        /**
         * Creates a map of monitor ids. In the case of bucket level monitors pairs are: RuleId -
         * MonitorId In the case of doc level monitor pair is DOC_LEVEL_MONITOR(value) - MonitorId
         *
         * @param monitorResponses index monitor responses
         * @return map of monitor ids
         */
        private Map<String, String> mapMonitorIds(List<IndexMonitorResponse> monitorResponses) {
            return monitorResponses.stream()
                    .collect(
                            Collectors.toMap(
                                    // In the case of bucket level monitors rule id is trigger id
                                    it -> {
                                        if (MonitorType.BUCKET_LEVEL_MONITOR
                                                .getValue()
                                                .equals(it.getMonitor().getMonitorType())) {
                                            return it.getMonitor().getTriggers().get(0).getId();
                                        } else {
                                            if (it.getMonitor().getName().contains("_chained_findings")) {
                                                return CHAINED_FINDINGS_MONITOR_STRING;
                                            } else {
                                                return Detector.DOC_LEVEL_MONITOR;
                                            }
                                        }
                                    },
                                    IndexMonitorResponse::getId));
        }
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }

    private void setEnabledWorkflowUsage(boolean enabledWorkflowUsage) {
        this.enabledWorkflowUsage = enabledWorkflowUsage;
    }

    private void setEnabledDetectorsWithDedicatedQueryIndices(
            boolean enabledDetectorsWithDedicatedQueryIndices) {
        this.enableDetectorWithDedicatedQueryIndices = enabledDetectorsWithDedicatedQueryIndices;
    }
}
