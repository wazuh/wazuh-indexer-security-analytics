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
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * PUT /_plugins/_security_analytics/findings/_update
 *
 * <p>Accepts a JSON object with a {@code findings} array. Each element must contain {@code _id},
 * {@code _index}, and a {@code case} object with the case-management fields to set.
 */
public class RestUpdateFindingsAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestUpdateFindingsAction.class);

    private static final String FIELD_FINDINGS = "findings";
    private static final String FIELD_ID = "_id";
    private static final String FIELD_INDEX = "_index";
    private static final String FIELD_CASE = "case";
    private static final String FIELD_WAZUH = "wazuh";
    private static final String FIELD_MESSAGE = "message";
    private static final String FIELD_STATUS = "status";
    private static final int MAX_BULK_ITEMS = 50;

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
        Map<String, Object> parsed;
        try {
            parsed = XContentHelper.convertToMap(request.content(), false, MediaTypeRegistry.JSON).v2();
        } catch (Exception e) {
            return channel ->
                    this.sendError(channel, RestStatus.BAD_REQUEST, "Invalid JSON body: " + e.getMessage());
        }

        Object findingsObj = parsed.get(FIELD_FINDINGS);
        if (!(findingsObj instanceof List)) {
            return channel ->
                    this.sendError(
                            channel,
                            RestStatus.BAD_REQUEST,
                            "Request body must contain a \"" + FIELD_FINDINGS + "\" array");
        }

        @SuppressWarnings("unchecked")
        List<Object> items = (List<Object>) findingsObj;

        return channel -> {
            if (items.isEmpty()) {
                this.sendError(channel, RestStatus.BAD_REQUEST, "Findings array is empty");
                return;
            }

            if (items.size() > MAX_BULK_ITEMS) {
                this.sendError(
                        channel,
                        RestStatus.BAD_REQUEST,
                        "Cannot update more than " + MAX_BULK_ITEMS + " findings at once");
                return;
            }

            BulkRequest bulkRequest = new BulkRequest();

            for (int i = 0; i < items.size(); i++) {
                Object item = items.get(i);
                if (!(item instanceof Map)) {
                    this.sendError(
                            channel, RestStatus.BAD_REQUEST, "Element at index " + i + " is not a JSON object");
                    return;
                }

                @SuppressWarnings("unchecked")
                Map<String, Object> entry = (Map<String, Object>) item;
                String id = (String) entry.get(FIELD_ID);
                String index = (String) entry.get(FIELD_INDEX);
                Object caseObj = entry.get(FIELD_CASE);

                if (id == null || id.isBlank()) {
                    this.sendError(
                            channel, RestStatus.BAD_REQUEST, "Element at index " + i + " is missing " + FIELD_ID);
                    return;
                }
                if (index == null || index.isBlank()) {
                    this.sendError(
                            channel,
                            RestStatus.BAD_REQUEST,
                            "Element at index " + i + " is missing " + FIELD_INDEX);
                    return;
                }
                if (!(caseObj instanceof Map)) {
                    this.sendError(
                            channel,
                            RestStatus.BAD_REQUEST,
                            "Element at index " + i + " is missing or invalid " + FIELD_CASE + " object");
                    return;
                }

                Map<String, Object> updateDoc = Map.of(FIELD_WAZUH, Map.of(FIELD_CASE, caseObj));
                UpdateRequest updateRequest =
                        new UpdateRequest(index, id).doc(updateDoc, MediaTypeRegistry.JSON);
                bulkRequest.add(updateRequest);
            }

            client.bulk(
                    bulkRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(BulkResponse bulkResponse) {
                            try (XContentBuilder builder = MediaTypeRegistry.JSON.contentBuilder()) {
                                builder.startObject();
                                builder.field("took", bulkResponse.getTook().millis());
                                builder.field("errors", bulkResponse.hasFailures());
                                builder.startArray("items");
                                for (BulkItemResponse item : bulkResponse) {
                                    builder.startObject();
                                    builder.field(FIELD_ID, item.getId());
                                    builder.field(FIELD_INDEX, item.getIndex());
                                    if (item.isFailed()) {
                                        BulkItemResponse.Failure failure = item.getFailure();
                                        RestStatus failStatus = failure != null ? failure.getStatus() : null;
                                        builder.field("status", failStatus != null ? failStatus.getStatus() : 500);
                                        builder.field("error", item.getFailureMessage());
                                    } else {
                                        builder.field("status", item.status().getStatus());
                                        builder.field("result", item.getResponse().getResult().getLowercase());
                                    }
                                    builder.endObject();
                                }
                                builder.endArray();
                                builder.endObject();

                                RestStatus status =
                                        bulkResponse.hasFailures() ? RestStatus.MULTI_STATUS : RestStatus.OK;
                                channel.sendResponse(new BytesRestResponse(status, builder));
                            } catch (Exception e) {
                                log.error("Failed to send bulk response", e);
                                RestUpdateFindingsAction.this.sendError(
                                        channel,
                                        RestStatus.INTERNAL_SERVER_ERROR,
                                        "Failed to build response: " + e.getMessage());
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Bulk update failed", e);
                            RestUpdateFindingsAction.this.sendError(
                                    channel,
                                    RestStatus.INTERNAL_SERVER_ERROR,
                                    "Bulk update failed: " + e.getMessage());
                        }
                    });
        };
    }

    private void sendError(RestChannel channel, RestStatus status, String message) {
        try (XContentBuilder builder = MediaTypeRegistry.JSON.contentBuilder()) {
            builder.startObject();
            builder.field(FIELD_MESSAGE, message);
            builder.field(FIELD_STATUS, status.getStatus());
            builder.endObject();
            channel.sendResponse(new BytesRestResponse(status, builder));
        } catch (IOException e) {
            log.error("Failed to send error response", e);
        }
    }
}
