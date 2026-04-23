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
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.DeleteDetectorAction;
import org.opensearch.securityanalytics.action.DeleteDetectorRequest;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.wazuh.securityanalytics.action.WDeleteSpaceResourcesAction;
import com.wazuh.securityanalytics.action.WDeleteSpaceResourcesRequest;
import com.wazuh.securityanalytics.action.WDeleteSpaceResourcesResponse;

/**
 * Transport action that bulk-deletes all Security Analytics resources belonging to a given space.
 *
 * <p>Deletion order matters due to referential constraints:
 *
 * <ol>
 *   <li><b>Detectors</b> — must go first; integrations cannot be deleted while detectors reference
 *       them.
 *   <li><b>Rules</b> — deleted via direct bulk request on both pre-packaged and custom indices.
 *   <li><b>Integrations</b> — deleted via direct bulk request on the log-type index.
 * </ol>
 *
 * <p>Rules and integrations are deleted directly (bypassing individual action validation) because
 * the prerequisite resources (detectors for integrations, detectors for rules) have already been
 * removed in earlier steps.
 */
public class WTransportDeleteSpaceResourcesAction
        extends HandledTransportAction<WDeleteSpaceResourcesRequest, WDeleteSpaceResourcesResponse>
        implements SecureTransportAction {

    private static final Logger log =
            LogManager.getLogger(WTransportDeleteSpaceResourcesAction.class);

    private static final String SPACE_KEYWORD_FIELD = "space.keyword";
    private static final String DETECTOR_NESTED_PATH = "detector";
    private static final String DETECTOR_TYPE_FIELD = "detector.detector_type";
    private static final String RULE_NESTED_PATH = "rule";
    private static final String INTEGRATION_NAME_FIELD = "name";
    private static final int MAX_RESULTS = 10000;

    private final Client client;

    @Inject
    public WTransportDeleteSpaceResourcesAction(
            TransportService transportService, Client client, ActionFilters actionFilters) {
        super(
                WDeleteSpaceResourcesAction.NAME,
                transportService,
                actionFilters,
                WDeleteSpaceResourcesRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(
            Task task,
            WDeleteSpaceResourcesRequest request,
            ActionListener<WDeleteSpaceResourcesResponse> listener) {
        String space = request.getSpace();
        WriteRequest.RefreshPolicy refreshPolicy = request.getRefreshPolicy();

        log.info("Deleting all Security Analytics resources for space [{}]", space);

        // Step 1: Discover integrations (need names to find associated detectors).
        this.findIntegrations(
                space,
                ActionListener.wrap(
                        integrations -> this.executeDelete(space, integrations, refreshPolicy, listener),
                        listener::onFailure));
    }

    /**
     * Orchestrates the sequential delete pipeline: detectors → rules → integrations.
     *
     * <p>Each step feeds its result count into the next. On failure at any step, a partial-success
     * response is returned so the caller knows what was cleaned up.
     */
    private void executeDelete(
            String space,
            List<IntegrationInfo> integrations,
            WriteRequest.RefreshPolicy refreshPolicy,
            ActionListener<WDeleteSpaceResourcesResponse> listener) {

        List<String> integrationNames = new ArrayList<>();
        for (IntegrationInfo info : integrations) {
            if (info.name != null && !info.name.isEmpty()) {
                integrationNames.add(info.name);
            }
        }

        // Step 2: Delete detectors that reference these integrations.
        this.deleteDetectors(
                integrationNames,
                refreshPolicy,
                ActionListener.wrap(
                        deletedDetectors ->
                                // Step 3: Bulk-delete rules.
                                this.bulkDeleteRules(
                                        space,
                                        refreshPolicy,
                                        ActionListener.wrap(
                                                deletedRules ->
                                                        // Step 4: Bulk-delete integrations.
                                                        this.bulkDeleteIntegrations(
                                                                integrations,
                                                                refreshPolicy,
                                                                ActionListener.wrap(
                                                                        deletedIntegrations -> {
                                                                            log.info(
                                                                                    "Space [{}] delete complete: "
                                                                                            + "[{}] detectors, [{}] rules, [{}] integrations",
                                                                                    space,
                                                                                    deletedDetectors,
                                                                                    deletedRules,
                                                                                    deletedIntegrations);
                                                                            listener.onResponse(
                                                                                    new WDeleteSpaceResourcesResponse(
                                                                                            deletedIntegrations, deletedRules, false, null));
                                                                        },
                                                                        e -> partialFailure(listener, 0, deletedRules, e))),
                                                e -> partialFailure(listener, 0, 0, e))),
                        e -> partialFailure(listener, 0, 0, e)));
    }

    /**
     * Finds and deletes all detectors whose {@code detector.detector_type} matches any of the given
     * integration names. Detectors are deleted sequentially via {@link DeleteDetectorAction} to
     * ensure proper resource cleanup (alerts, findings, etc.).
     */
    private void deleteDetectors(
            List<String> integrationNames,
            WriteRequest.RefreshPolicy refreshPolicy,
            ActionListener<Integer> listener) {
        if (integrationNames.isEmpty()) {
            listener.onResponse(0);
            return;
        }

        SearchSourceBuilder source =
                new SearchSourceBuilder()
                        .query(
                                QueryBuilders.nestedQuery(
                                        DETECTOR_NESTED_PATH,
                                        QueryBuilders.termsQuery(DETECTOR_TYPE_FIELD, integrationNames),
                                        ScoreMode.None))
                        .size(MAX_RESULTS)
                        .fetchSource(false);

        this.client.search(
                new SearchRequest(Detector.DETECTORS_INDEX).source(source),
                ActionListener.wrap(
                        response -> {
                            List<String> ids = collectIds(response);
                            this.deleteDetectorsSequentially(
                                    ids.iterator(), refreshPolicy, new AtomicInteger(0), listener);
                        },
                        e -> resolveOrFail(e, listener)));
    }

    private void deleteDetectorsSequentially(
            Iterator<String> iterator,
            WriteRequest.RefreshPolicy refreshPolicy,
            AtomicInteger deleted,
            ActionListener<Integer> listener) {
        if (!iterator.hasNext()) {
            listener.onResponse(deleted.get());
            return;
        }

        String id = iterator.next();
        this.client.execute(
                DeleteDetectorAction.INSTANCE,
                new DeleteDetectorRequest(id, refreshPolicy),
                ActionListener.wrap(
                        response -> {
                            deleted.incrementAndGet();
                            this.deleteDetectorsSequentially(iterator, refreshPolicy, deleted, listener);
                        },
                        e -> {
                            log.warn("Failed to delete detector [{}]: {}", id, e.getMessage());
                            this.deleteDetectorsSequentially(iterator, refreshPolicy, deleted, listener);
                        }));
    }

    /**
     * Finds and bulk-deletes all rules (pre-packaged and custom) that belong to the given space.
     * Rules store their space in a nested {@code rule.space} field.
     */
    private void bulkDeleteRules(
            String space, WriteRequest.RefreshPolicy refreshPolicy, ActionListener<Integer> listener) {

        this.findRuleIds(
                Rule.PRE_PACKAGED_RULES_INDEX,
                space,
                ActionListener.wrap(
                        prePackagedIds ->
                                this.findRuleIds(
                                        Rule.CUSTOM_RULES_INDEX,
                                        space,
                                        ActionListener.wrap(
                                                customIds -> {
                                                    BulkRequest bulk = new BulkRequest();
                                                    for (String id : prePackagedIds) {
                                                        bulk.add(new DeleteRequest(Rule.PRE_PACKAGED_RULES_INDEX, id));
                                                    }
                                                    for (String id : customIds) {
                                                        bulk.add(new DeleteRequest(Rule.CUSTOM_RULES_INDEX, id));
                                                    }
                                                    this.executeBulkDelete(bulk, refreshPolicy, listener);
                                                },
                                                listener::onFailure)),
                        listener::onFailure));
    }

    private void findRuleIds(String ruleIndex, String space, ActionListener<List<String>> listener) {
        SearchSourceBuilder source =
                new SearchSourceBuilder()
                        .query(
                                QueryBuilders.nestedQuery(
                                        RULE_NESTED_PATH,
                                        QueryBuilders.termQuery(RULE_NESTED_PATH + "." + Rule.SPACE_FIELD, space),
                                        ScoreMode.None))
                        .size(MAX_RESULTS)
                        .fetchSource(false);

        this.client.search(
                new SearchRequest(ruleIndex).source(source),
                ActionListener.wrap(
                        response -> listener.onResponse(collectIds(response)),
                        e -> resolveOrFail(e, listener)));
    }

    /**
     * Bulk-deletes integration documents directly from the log-type index. Safe to call after
     * detectors and rules have been removed.
     */
    private void bulkDeleteIntegrations(
            List<IntegrationInfo> integrations,
            WriteRequest.RefreshPolicy refreshPolicy,
            ActionListener<Integer> listener) {
        BulkRequest bulk = new BulkRequest();
        for (IntegrationInfo info : integrations) {
            bulk.add(new DeleteRequest(LogTypeService.LOG_TYPE_INDEX, info.id));
        }
        this.executeBulkDelete(bulk, refreshPolicy, listener);
    }

    /** Finds all integrations (log types) in the log-type index that belong to the given space. */
    private void findIntegrations(String space, ActionListener<List<IntegrationInfo>> listener) {
        SearchSourceBuilder source =
                new SearchSourceBuilder()
                        .query(QueryBuilders.termQuery(SPACE_KEYWORD_FIELD, space))
                        .size(MAX_RESULTS)
                        .fetchSource(new String[] {INTEGRATION_NAME_FIELD}, null);

        this.client.search(
                new SearchRequest(LogTypeService.LOG_TYPE_INDEX).source(source),
                ActionListener.wrap(
                        response -> {
                            List<IntegrationInfo> result = new ArrayList<>();
                            for (SearchHit hit : response.getHits().getHits()) {
                                String name = null;
                                Map<String, Object> src = hit.getSourceAsMap();
                                if (src != null && src.containsKey(INTEGRATION_NAME_FIELD)) {
                                    name = (String) src.get(INTEGRATION_NAME_FIELD);
                                }
                                result.add(new IntegrationInfo(hit.getId(), name));
                            }
                            listener.onResponse(result);
                        },
                        e -> resolveOrFail(e, listener)));
    }

    /**
     * Executes a bulk delete request and counts successful items. Logs a warning if any items fail.
     * Returns 0 immediately if the request has no actions.
     */
    private void executeBulkDelete(
            BulkRequest bulk,
            WriteRequest.RefreshPolicy refreshPolicy,
            ActionListener<Integer> listener) {
        if (bulk.numberOfActions() == 0) {
            listener.onResponse(0);
            return;
        }

        bulk.setRefreshPolicy(refreshPolicy);
        this.client.bulk(
                bulk,
                ActionListener.wrap(
                        response -> {
                            int successCount = 0;
                            for (BulkItemResponse item : response.getItems()) {
                                if (item.isFailed()) {
                                    log.warn(
                                            "Bulk delete item [{}] failed: {}", item.getId(), item.getFailureMessage());
                                } else {
                                    successCount++;
                                }
                            }
                            listener.onResponse(successCount);
                        },
                        listener::onFailure));
    }

    /** Collects all {@code _id} values from a search response. */
    private static List<String> collectIds(org.opensearch.action.search.SearchResponse response) {
        List<String> ids = new ArrayList<>();
        for (SearchHit hit : response.getHits().getHits()) {
            ids.add(hit.getId());
        }
        return ids;
    }

    /**
     * If the exception is an {@link IndexNotFoundException}, resolves with an empty result; otherwise
     * propagates the failure.
     */
    @SuppressWarnings("unchecked")
    private static <T> void resolveOrFail(Exception e, ActionListener<T> listener) {
        if (e instanceof IndexNotFoundException
                || (e.getCause() != null && e.getCause() instanceof IndexNotFoundException)) {
            // Index does not exist — nothing to delete / return empty list.
            try {
                listener.onResponse((T) new ArrayList<>());
            } catch (ClassCastException cce) {
                listener.onResponse((T) Integer.valueOf(0));
            }
        } else {
            listener.onFailure(e);
        }
    }

    /** Returns a partial-success response, logging the failure. */
    private static void partialFailure(
            ActionListener<WDeleteSpaceResourcesResponse> listener,
            int deletedIntegrations,
            int deletedRules,
            Exception e) {
        log.error("Space resource deletion failed partially: {}", e.getMessage());
        listener.onResponse(
                new WDeleteSpaceResourcesResponse(deletedIntegrations, deletedRules, true, e.getMessage()));
    }

    /** Holds an integration {@code _id} and its logical name. */
    private static class IntegrationInfo {
        final String id;
        final String name;

        IntegrationInfo(String id, String name) {
            this.id = id;
            this.name = name;
        }
    }
}
