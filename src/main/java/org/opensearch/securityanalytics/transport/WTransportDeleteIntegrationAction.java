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

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeAction;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeRequest;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeResponse;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import com.wazuh.securityanalytics.action.WDeleteIntegrationAction;
import com.wazuh.securityanalytics.action.WDeleteIntegrationRequest;
import com.wazuh.securityanalytics.action.WDeleteIntegrationResponse;

public class WTransportDeleteIntegrationAction
        extends HandledTransportAction<WDeleteIntegrationRequest, WDeleteIntegrationResponse>
        implements SecureTransportAction {
    private final Client client;
    private static final Logger log = LogManager.getLogger(WTransportDeleteIntegrationAction.class);

    private static final String DOCUMENT_ID_FIELD = "document.id";
    private static final String SOURCE_FIELD = "source";

    @Inject
    public WTransportDeleteIntegrationAction(
            TransportService transportService, Client client, ActionFilters actionFilters) {
        super(
                WDeleteIntegrationAction.NAME,
                transportService,
                actionFilters,
                WDeleteIntegrationRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(
            Task task,
            WDeleteIntegrationRequest request,
            ActionListener<WDeleteIntegrationResponse> listener) {
        if (request.getDocumentId() != null && request.getSource() != null) {
            this.resolveAndDelete(request, listener);
        } else {
            this.deleteById(request.getLogTypeId(), request.getRefreshPolicy(), listener);
        }
    }

    private void resolveAndDelete(
            WDeleteIntegrationRequest request,
            ActionListener<WDeleteIntegrationResponse> listener) {
        BoolQueryBuilder query =
                QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery(DOCUMENT_ID_FIELD, request.getDocumentId()))
                        .must(
                                QueryBuilders.termQuery(
                                        SOURCE_FIELD + ".keyword", request.getSource()));

        SearchSourceBuilder searchSource = new SearchSourceBuilder().query(query).size(1);
        SearchRequest searchRequest =
                new SearchRequest(LogTypeService.LOG_TYPE_INDEX).source(searchSource);

        this.client.search(
                searchRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse searchResponse) {
                        SearchHit[] hits = searchResponse.getHits().getHits();
                        if (hits.length == 0) {
                            log.warn(
                                    "No integration found with document.id [{}] and source [{}]",
                                    request.getDocumentId(),
                                    request.getSource());
                            listener.onFailure(
                                    new org.opensearch.OpenSearchStatusException(
                                            "Integration not found for document.id ["
                                                    + request.getDocumentId()
                                                    + "] and source ["
                                                    + request.getSource()
                                                    + "]",
                                            org.opensearch.core.rest.RestStatus.NOT_FOUND));
                            return;
                        }
                        String resolvedId = hits[0].getId();
                        log.info(
                                "Resolved integration document.id [{}] source [{}] to _id [{}]",
                                request.getDocumentId(),
                                request.getSource(),
                                resolvedId);
                        WTransportDeleteIntegrationAction.this.deleteById(
                                resolvedId, request.getRefreshPolicy(), listener);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(
                                "Failed to search for integration by document.id: {}",
                                e.getMessage());
                        listener.onFailure(e);
                    }
                });
    }

    private void deleteById(
            String logTypeId,
            org.opensearch.action.support.WriteRequest.RefreshPolicy refreshPolicy,
            ActionListener<WDeleteIntegrationResponse> listener) {
        DeleteCustomLogTypeRequest internalRequest =
                new DeleteCustomLogTypeRequest(logTypeId, refreshPolicy);
        this.client.execute(
                DeleteCustomLogTypeAction.INSTANCE,
                internalRequest,
                new ActionListener<DeleteCustomLogTypeResponse>() {
                    @Override
                    public void onResponse(DeleteCustomLogTypeResponse response) {
                        log.info(
                                "Successfully deleted integration with id: {}", response.getId());
                        listener.onResponse(
                                new WDeleteIntegrationResponse(
                                        response.getId(),
                                        response.getVersion(),
                                        response.getStatus()));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
    }
}
