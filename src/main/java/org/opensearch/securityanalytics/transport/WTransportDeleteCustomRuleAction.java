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
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.DeleteRuleAction;
import org.opensearch.securityanalytics.action.DeleteRuleRequest;
import org.opensearch.securityanalytics.action.DeleteRuleResponse;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import com.wazuh.securityanalytics.action.WDeleteCustomRuleAction;
import com.wazuh.securityanalytics.action.WDeleteCustomRuleRequest;
import com.wazuh.securityanalytics.action.WDeleteRuleResponse;

public class WTransportDeleteCustomRuleAction
        extends HandledTransportAction<WDeleteCustomRuleRequest, WDeleteRuleResponse>
        implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(WTransportDeleteCustomRuleAction.class);
    private final Client client;

    @Inject
    public WTransportDeleteCustomRuleAction(
            TransportService transportService, Client client, ActionFilters actionFilters) {
        super(
                WDeleteCustomRuleAction.NAME,
                transportService,
                actionFilters,
                WDeleteCustomRuleRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(
            Task task, WDeleteCustomRuleRequest request, ActionListener<WDeleteRuleResponse> listener) {
        if (request.getDocumentId() != null && request.getSpace() != null) {
            // Search by document.id + source, then delete the found document.
            this.resolveAndDelete(task, request, listener);
        } else {
            this.deleteById(
                    task, request.getRuleId(), request.getRefreshPolicy(), request.isForced(), listener);
        }
    }

    private void resolveAndDelete(
            Task task, WDeleteCustomRuleRequest request, ActionListener<WDeleteRuleResponse> listener) {
        // Rules are stored in a nested "rule" object; query nested fields.
        SearchSourceBuilder searchSource =
                new SearchSourceBuilder()
                        .query(
                                QueryBuilders.nestedQuery(
                                        "rule",
                                        QueryBuilders.boolQuery()
                                                .must(
                                                        QueryBuilders.termQuery(
                                                                "rule." + Rule.DOCUMENT_ID_FIELD, request.getDocumentId()))
                                                .must(
                                                        QueryBuilders.termQuery(
                                                                "rule." + Rule.SPACE_FIELD, request.getSpace())),
                                        ScoreMode.None))
                        .size(1);
        SearchRequest searchRequest = new SearchRequest(Rule.CUSTOM_RULES_INDEX).source(searchSource);

        this.client.search(
                searchRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse searchResponse) {
                        SearchHit[] hits = searchResponse.getHits().getHits();
                        if (hits.length == 0) {
                            log.warn(
                                    "No custom rule found with document.id [{}] and space [{}]",
                                    request.getDocumentId(),
                                    request.getSpace());
                            listener.onFailure(
                                    new org.opensearch.OpenSearchStatusException(
                                            "Rule not found for document.id ["
                                                    + request.getDocumentId()
                                                    + "] and space ["
                                                    + request.getSpace()
                                                    + "]",
                                            org.opensearch.core.rest.RestStatus.NOT_FOUND));
                            return;
                        }
                        String resolvedId = hits[0].getId();
                        log.info(
                                "Resolved custom rule document.id [{}] space [{}] to _id [{}]",
                                request.getDocumentId(),
                                request.getSpace(),
                                resolvedId);
                        WTransportDeleteCustomRuleAction.this.deleteById(
                                task, resolvedId, request.getRefreshPolicy(), request.isForced(), listener);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to search for custom rule by document.id: {}", e.getMessage());
                        listener.onFailure(e);
                    }
                });
    }

    private void deleteById(
            Task task,
            String ruleId,
            org.opensearch.action.support.WriteRequest.RefreshPolicy refreshPolicy,
            Boolean forced,
            ActionListener<WDeleteRuleResponse> listener) {
        DeleteRuleRequest internalRequest = new DeleteRuleRequest(ruleId, refreshPolicy, forced);
        this.client.execute(
                DeleteRuleAction.INSTANCE,
                internalRequest,
                new ActionListener<DeleteRuleResponse>() {
                    @Override
                    public void onResponse(DeleteRuleResponse response) {
                        log.info("Successfully deleted custom rule with id: {}", response.getId());
                        listener.onResponse(
                                new WDeleteRuleResponse(
                                        response.getId(), response.getVersion(), response.getStatus()));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to delete custom rule via default action: {}", e.getMessage());
                        listener.onFailure(e);
                    }
                });
    }
}
