/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WDeleteRuleAction;
import com.wazuh.securityanalytics.action.WDeleteRuleRequest;
import com.wazuh.securityanalytics.action.WDeleteRuleResponse;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.DeleteRuleRequest;
import org.opensearch.securityanalytics.action.DeleteRuleResponse;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

public class WTransportDeleteRuleAction extends HandledTransportAction<WDeleteRuleRequest, WDeleteRuleResponse>
    implements
        SecureTransportAction {

    private final TransportDeleteRuleAction internalAction;
    private final Client client;

    @Inject
    public WTransportDeleteRuleAction(
        TransportService transportService,
        Client client,
        DetectorIndices detectorIndices,
        ActionFilters actionFilters,
        NamedXContentRegistry xContentRegistry
    ) {
        super(WDeleteRuleAction.NAME, transportService, actionFilters, WDeleteRuleRequest::new);
        this.client = client;
        this.internalAction = this.createInternalAction(transportService, client, detectorIndices, actionFilters, xContentRegistry);
    }

    @Override
    protected void doExecute(Task task, WDeleteRuleRequest request, ActionListener<WDeleteRuleResponse> listener) {
        if (request.getDocumentId() != null && request.getSource() != null) {
            this.resolveAndDelete(task, request, listener);
        } else {
            this.deleteById(task, request.getRuleId(), request.getRefreshPolicy(), request.isForced(), listener);
        }
    }

    private void resolveAndDelete(Task task, WDeleteRuleRequest request, ActionListener<WDeleteRuleResponse> listener) {
        // Rules are stored in a nested "rule" object; query nested fields.
        SearchSourceBuilder searchSource = new SearchSourceBuilder()
            .query(
                QueryBuilders.nestedQuery(
                    "rule",
                    QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery("rule." + Rule.DOCUMENT_ID_FIELD, request.getDocumentId()))
                        .must(QueryBuilders.termQuery("rule." + Rule.SOURCE_FIELD, request.getSource())),
                    ScoreMode.None
                )
            )
            .size(1);
        SearchRequest searchRequest = new SearchRequest(Rule.PRE_PACKAGED_RULES_INDEX).source(searchSource);

        this.client.search(searchRequest, new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                SearchHit[] hits = searchResponse.getHits().getHits();
                if (hits.length == 0) {
                    log.warn(
                        "No pre-packaged rule found with document.id [{}] and source [{}]",
                        request.getDocumentId(),
                        request.getSource()
                    );
                    listener.onFailure(
                        new org.opensearch.OpenSearchStatusException(
                            "Rule not found for document.id [" + request.getDocumentId() + "] and source [" + request.getSource() + "]",
                            org.opensearch.core.rest.RestStatus.NOT_FOUND
                        )
                    );
                    return;
                }
                String resolvedId = hits[0].getId();
                log.info(
                    "Resolved pre-packaged rule document.id [{}] source [{}] to _id [{}]",
                    request.getDocumentId(),
                    request.getSource(),
                    resolvedId
                );
                WTransportDeleteRuleAction.this.deleteById(task, resolvedId, request.getRefreshPolicy(), request.isForced(), listener);
            }

            @Override
            public void onFailure(Exception e) {
                log.error("Failed to search for pre-packaged rule by document.id: {}", e.getMessage());
                listener.onFailure(e);
            }
        });
    }

    private void deleteById(
        Task task,
        String ruleId,
        org.opensearch.action.support.WriteRequest.RefreshPolicy refreshPolicy,
        Boolean forced,
        ActionListener<WDeleteRuleResponse> listener
    ) {
        DeleteRuleRequest internalRequest = new DeleteRuleRequest(ruleId, refreshPolicy, forced);
        this.internalAction.doExecute(task, internalRequest, new ActionListener<>() {
            @Override
            public void onResponse(DeleteRuleResponse response) {
                log.info("Successfully deleted rule with id: {}", response.getId());
                listener.onResponse(new WDeleteRuleResponse(response.getId(), response.getVersion(), response.getStatus()));
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    /**
     * Creates the internal action using the PRE_PACKAGED_RULES_INDEX to allow deletion of Wazuh rules
     *
     * Method created to allow tests to mock the action
     */
    protected TransportDeleteRuleAction createInternalAction(
        TransportService transportService,
        Client client,
        DetectorIndices detectorIndices,
        ActionFilters actionFilters,
        NamedXContentRegistry xContentRegistry
    ) {
        return new TransportDeleteRuleAction(
            WDeleteRuleAction.NAME + "/internal",
            transportService,
            client,
            detectorIndices,
            actionFilters,
            xContentRegistry,
            Rule.PRE_PACKAGED_RULES_INDEX
        );
    }
}
