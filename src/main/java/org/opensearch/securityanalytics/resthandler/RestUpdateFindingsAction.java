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
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;
import java.util.Map;

/**
 * PUT /_plugins/_security_analytics/findings/{finding_id}/case
 *
 * <p>Updates case management fields on a finding document that lives inside a data stream. Resolves
 * the backing index via a _search (since GET doesn't resolve data stream wildcards), then targets
 * _update directly on the backing index.
 */
public class RestUpdateFindingsAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestUpdateFindingsAction.class);

    private static final String FINDINGS_PATTERN = "wazuh-findings-v5-*";

    @Override
    public String getName() {
        return "wazuh_update_finding_case";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .uniqueName("plugin:wazuh/findings/case/update")
                        .method(RestRequest.Method.PUT)
                        .path(SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_update")
                        .build());
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String findingId = request.param("finding_id");
        String body = request.content().utf8ToString();

        return channel -> {
            // Step 1: Search for the doc by _id to resolve the backing index
            SearchRequest searchRequest = new SearchRequest(FINDINGS_PATTERN);
            searchRequest.source(
                    new SearchSourceBuilder().query(QueryBuilders.idsQuery().addIds(findingId)).size(1));

            client.search(
                    searchRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(SearchResponse searchResponse) {
                            if (searchResponse.getHits().getTotalHits().value() == 0) {
                                RestUpdateFindingsAction.sendError(
                                        channel, RestStatus.NOT_FOUND, "Finding [" + findingId + "] not found");
                                return;
                            }

                            SearchHit hit = searchResponse.getHits().getHits()[0];
                            String backingIndex = hit.getIndex();
                            log.info("Resolved finding [{}] to backing index [{}]", findingId, backingIndex);

                            // Step 2: Parse the body as case fields
                            Map<String, Object> caseFields;
                            try {
                                @SuppressWarnings("unchecked")
                                Map<String, Object> parsed =
                                        org.opensearch.common.xcontent.XContentHelper.convertToMap(
                                                MediaTypeRegistry.JSON.xContent(), body, false);
                                caseFields = parsed;
                            } catch (Exception e) {
                                RestUpdateFindingsAction.sendError(
                                        channel, RestStatus.BAD_REQUEST, "Invalid JSON body: " + e.getMessage());
                                return;
                            }

                            // Step 3: _update directly on the backing index
                            Map<String, Object> updateDoc = Map.of("wazuh", Map.of("case", caseFields));

                            UpdateRequest updateRequest =
                                    new UpdateRequest(backingIndex, findingId).doc(updateDoc, MediaTypeRegistry.JSON);

                            client.update(
                                    updateRequest,
                                    new ActionListener<>() {
                                        @Override
                                        public void onResponse(UpdateResponse updateResponse) {
                                            try {
                                                channel.sendResponse(
                                                        new BytesRestResponse(
                                                                RestStatus.OK,
                                                                "application/json",
                                                                "{\"message\":\"Case updated\","
                                                                        + "\"backing_index\":\""
                                                                        + backingIndex
                                                                        + "\","
                                                                        + "\"result\":\""
                                                                        + updateResponse.getResult().getLowercase()
                                                                        + "\"}"));
                                            } catch (Exception e) {
                                                log.error("Failed to send response", e);
                                            }
                                        }

                                        @Override
                                        public void onFailure(Exception e) {
                                            log.error("Failed to update finding case", e);
                                            RestUpdateFindingsAction.sendError(
                                                    channel,
                                                    RestStatus.INTERNAL_SERVER_ERROR,
                                                    "Update failed: " + e.getMessage());
                                        }
                                    });
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to resolve finding", e);
                            RestUpdateFindingsAction.sendError(
                                    channel, RestStatus.INTERNAL_SERVER_ERROR, "Resolve failed: " + e.getMessage());
                        }
                    });
        };
    }

    private static void sendError(RestChannel channel, RestStatus status, String message) {
        try {
            channel.sendResponse(
                    new BytesRestResponse(
                            status,
                            "application/json",
                            "{\"message\":\""
                                    + message.replace("\"", "\\\"")
                                    + "\","
                                    + "\"status\":"
                                    + status.getStatus()
                                    + "}"));
        } catch (Exception e) {
            log.error("Failed to send error response", e);
        }
    }
}
