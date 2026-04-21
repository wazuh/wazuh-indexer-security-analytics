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
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.util.DetectorFactory;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wazuh.securityanalytics.action.WIndexDetectorAction;
import com.wazuh.securityanalytics.action.WIndexDetectorRequest;
import com.wazuh.securityanalytics.action.WIndexDetectorResponse;

import static org.opensearch.securityanalytics.transport.TransportIndexDetectorAction.WAZUH_INTERNAL_CALLER_HEADER;

/**
 * Transport action handler for indexing Wazuh detectors.
 *
 * <p>This class handles the transport-level execution of detector indexing requests, converting
 * external {@link WIndexDetectorRequest} objects into internal {@link IndexDetectorRequest} objects
 * and delegating to the standard detector indexing action.
 *
 * <p>The action uses {@link DetectorFactory} to create detector instances from the provided log
 * type name, category, and rules before persisting them.
 *
 * @see WIndexDetectorAction
 * @see WIndexDetectorRequest
 * @see WIndexDetectorResponse
 * @see DetectorFactory
 */
public class WTransportIndexDetectorAction
        extends HandledTransportAction<WIndexDetectorRequest, WIndexDetectorResponse>
        implements SecureTransportAction {
    private final Client client;
    private static final Logger log = LogManager.getLogger(WTransportIndexDetectorAction.class);

    // Constant for the CTI Integrations index
    private static final String CTI_INTEGRATIONS_INDEX = "wazuh-threatintel-integrations";

    /**
     * Constructs a new WTransportIndexDetectorAction.
     *
     * @param transportService the transport service for inter-node communication
     * @param client the OpenSearch client for executing internal actions
     * @param actionFilters filters to apply to the action execution
     */
    @Inject
    public WTransportIndexDetectorAction(
            TransportService transportService, Client client, ActionFilters actionFilters) {
        super(WIndexDetectorAction.NAME, transportService, actionFilters, WIndexDetectorRequest::new);
        this.client = client;
    }

    /**
     * Executes the detector indexing action.
     *
     * <p>This method performs the following steps: 1. Creates a new {@link Detector} using {@link
     * DetectorFactory} with the log type, category, and rules 2. Sets the detector ID from the
     * request 3. Wraps it in an {@link IndexDetectorRequest} with PUT method 4. Executes the indexing
     * action through the client 5. Returns the result via the provided listener
     *
     * @param task the task associated with this action execution
     * @param request the detector indexing request containing log type, category, and rules
     * @param listener the listener to notify upon completion or failure
     */
    @Override
    protected void doExecute(
            Task task, WIndexDetectorRequest request, ActionListener<WIndexDetectorResponse> listener) {

        // Fetch the integration document from wazuh-threatintel-integrations to get the true list of
        // rules
        SearchRequest integrationSearch = new SearchRequest(CTI_INTEGRATIONS_INDEX);
        integrationSearch.indicesOptions(IndicesOptions.lenientExpandOpen());

        SearchSourceBuilder intSourceBuilder = new SearchSourceBuilder();
        intSourceBuilder.query(
                QueryBuilders.matchQuery("document.metadata.title", request.getLogTypeName()));
        intSourceBuilder.size(1);
        integrationSearch.source(intSourceBuilder);

        this.client.search(
                integrationSearch,
                new ActionListener<SearchResponse>() {
                    @Override
                    @SuppressWarnings("unchecked")
                    public void onResponse(SearchResponse intResponse) {
                        if (intResponse.getHits().getHits().length == 0) {
                            log.warn(
                                    "Integration [{}] not found in {}",
                                    request.getLogTypeName(),
                                    CTI_INTEGRATIONS_INDEX);
                            WTransportIndexDetectorAction.this.validateRulesAndCreateDetector(
                                    request.getRules(), request, listener);
                            return;
                        }

                        Map<String, Object> sourceAsMap = intResponse.getHits().getHits()[0].getSourceAsMap();
                        Map<String, Object> documentMap = (Map<String, Object>) sourceAsMap.get("document");

                        List<String> expectedRuleIds = null;
                        if (documentMap != null) {
                            expectedRuleIds = (List<String>) documentMap.get("rules");
                        }

                        if (expectedRuleIds == null || expectedRuleIds.isEmpty()) {
                            log.debug(
                                    "Integration [{}] found in {} but has no rules listed. "
                                            + "Proceeding with rules from request: {}",
                                    request.getLogTypeName(),
                                    CTI_INTEGRATIONS_INDEX,
                                    request.getRules());
                            WTransportIndexDetectorAction.this.executeDetectorCreation(
                                    request, listener, request.getRules());
                            return;
                        }
                        log.debug(
                                "Integration [{}] found with {} expected rules. Validating...",
                                request.getLogTypeName(),
                                expectedRuleIds.size());
                        WTransportIndexDetectorAction.this.validateRulesAndCreateDetector(
                                expectedRuleIds, request, listener);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to query " + CTI_INTEGRATIONS_INDEX + " for detector creation", e);
                        listener.onFailure(e);
                    }
                });
    }

    /**
     * Validates a list of expected rule IDs against the internal rule indices before creating the
     * detector. *
     *
     * <p>This method queries OpenSearch to ensure the expected rules exist and are not residing
     * within invalid spaces (e.g., "draft" or "test"). If any rules are in an invalid space, it will
     * fail the request. Missing rules are logged as warnings but ignored. Finally, it proceeds to
     * create the detector strictly with the validated rules. * @param expectedRuleIds the list of
     * rule IDs fetched from the integration document to validate
     *
     * @param request the original detector indexing request
     * @param listener the listener to notify upon successful creation or validation failure
     */
    @SuppressWarnings("unchecked")
    private void validateRulesAndCreateDetector(
            List<String> expectedRuleIds,
            WIndexDetectorRequest request,
            ActionListener<WIndexDetectorResponse> listener) {
        if (expectedRuleIds == null || expectedRuleIds.isEmpty()) {
            this.executeDetectorCreation(
                    request, listener, expectedRuleIds == null ? new ArrayList<>() : expectedRuleIds);
            return;
        }

        SearchRequest searchRequest =
                new SearchRequest(Rule.CUSTOM_RULES_INDEX, Rule.PRE_PACKAGED_RULES_INDEX);
        searchRequest.indicesOptions(IndicesOptions.lenientExpandOpen());

        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();

        sourceBuilder.query(
                QueryBuilders.nestedQuery(
                        "rule", QueryBuilders.termsQuery("rule.document.id", expectedRuleIds), ScoreMode.None));

        sourceBuilder.size(Math.min(expectedRuleIds.size(), 10000));
        searchRequest.source(sourceBuilder);

        this.client.search(
                searchRequest,
                new ActionListener<SearchResponse>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        List<String> invalidSpaceRules = new ArrayList<>();
                        Set<String> foundRuleIds = new HashSet<>();

                        for (var hit : response.getHits().getHits()) {
                            Map<String, Object> sourceMap = hit.getSourceAsMap();
                            Map<String, Object> ruleMap = (Map<String, Object>) sourceMap.get("rule");

                            String docId = null;
                            String spaceSource = null;

                            if (ruleMap != null) {
                                docId = (String) ruleMap.get("document.id");
                                spaceSource = (String) ruleMap.get("space");
                            }

                            if (docId == null) {
                                docId = hit.getId();
                            }

                            foundRuleIds.add(docId);

                            if ("draft".equalsIgnoreCase(spaceSource) || "test".equalsIgnoreCase(spaceSource)) {
                                invalidSpaceRules.add(docId);
                            }
                        }

                        List<String> missingRules = new ArrayList<>();
                        List<String> validRulesToKeep = new ArrayList<>();

                        // Filter rules: track missing, and collect only the valid ones
                        for (String expectedId : expectedRuleIds) {
                            if (!foundRuleIds.contains(expectedId)) {
                                missingRules.add(expectedId);
                            } else if (!invalidSpaceRules.contains(expectedId)) {
                                validRulesToKeep.add(expectedId);
                            }
                        }

                        if (!invalidSpaceRules.isEmpty()) {
                            String errorMsg =
                                    String.format(
                                            "Cannot create [%s] detector. Rules %s are in draft/test space.",
                                            request.getLogTypeName(), invalidSpaceRules);
                            log.warn(errorMsg);
                            listener.onFailure(new OpenSearchStatusException(errorMsg, RestStatus.BAD_REQUEST));
                            return;
                        }

                        if (!missingRules.isEmpty()) {
                            log.warn(
                                    "The following rules for [{}] detector are missing or failed to sync: {}",
                                    request.getLogTypeName(),
                                    missingRules);
                        }

                        log.debug(
                                "Rule validation for [{}]: expected={}, found={}, valid={}, missing={}, invalidSpace={}",
                                request.getLogTypeName(),
                                expectedRuleIds.size(),
                                foundRuleIds.size(),
                                validRulesToKeep.size(),
                                missingRules.size(),
                                invalidSpaceRules.size());

                        // Proceed to creation with ONLY the valid, existing rules
                        WTransportIndexDetectorAction.this.executeDetectorCreation(
                                request, listener, validRulesToKeep);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(
                                "Failed to validate rules against SAP indices. Target rules: " + expectedRuleIds,
                                e);
                        listener.onFailure(e);
                    }
                });
    }

    /**
     * Constructs the detector and executes the internal index action using the validated rules. *
     *
     * <p>It utilizes the {@link DetectorFactory} to map the original request parameters alongside the
     * sanitized list of rule IDs into a new {@link Detector} instance, which is then submitted to
     * OpenSearch via the standard {@link IndexDetectorAction}. * @param request the original detector
     * indexing request
     *
     * @param listener the listener to pass back the final {@link WIndexDetectorResponse} upon
     *     completion
     * @param validRuleIds the sanitized list of valid rule IDs to associate with the detector
     */
    private void executeDetectorCreation(
            WIndexDetectorRequest request,
            ActionListener<WIndexDetectorResponse> listener,
            List<String> validRuleIds) {
        Detector detector =
                DetectorFactory.createDetector(
                        request.getLogTypeName(), request.getCategory(), validRuleIds);
        detector.setId(request.getDetectorId());

        IndexDetectorRequest indexDetectorRequest =
                new IndexDetectorRequest(
                        detector.getId(), request.getRefreshPolicy(), RestRequest.Method.PUT, detector);

        // Mark this request as coming from the Content Manager so that
        // TransportIndexDetectorAction allows modifications to standard detectors.
        if (this.client.threadPool().getThreadContext().getHeader(WAZUH_INTERNAL_CALLER_HEADER)
                == null) {
            this.client
                    .threadPool()
                    .getThreadContext()
                    .putHeader(WAZUH_INTERNAL_CALLER_HEADER, "content-manager");
        }

        this.client.execute(
                IndexDetectorAction.INSTANCE,
                indexDetectorRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexDetectorResponse response) {
                        log.info(
                                "Successfully indexed detector for [{}] with id: {}",
                                request.getLogTypeName(),
                                response.getId());
                        listener.onResponse(
                                new WIndexDetectorResponse(response.getId(), response.getVersion()));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
    }
}
