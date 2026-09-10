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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleAction;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleRequest;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleResponse;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

public class RestIndexCorrelationRuleAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestIndexCorrelationRuleAction.class);

    @Override
    public String getName() {
        return "index_correlation_rule_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI),
                new Route(
                        RestRequest.Method.PUT,
                        String.format(
                                Locale.getDefault(),
                                "%s/{%s}",
                                SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI,
                                "correlation_rule_id")));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        log.debug(
                String.format(
                        Locale.ROOT,
                        "%s %s",
                        request.method(),
                        SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI));

        String id = request.param("correlation_rule_id", CorrelationRule.NO_ID);

        // Forwarded verbatim and parsed by TransportIndexCorrelationRuleAction, so the parse happens
        // behind the ActionFilters chain that decides whether this account may write rules at all.
        byte[] body = request.hasContent() ? request.content().streamInput().readAllBytes() : null;
        String mediaType =
                request.getMediaType() != null ? request.getMediaType().mediaTypeWithoutParameters() : null;

        IndexCorrelationRuleRequest indexCorrelationRuleRequest =
                new IndexCorrelationRuleRequest(id, request.method(), body, mediaType);
        return channel ->
                client.execute(
                        IndexCorrelationRuleAction.INSTANCE,
                        indexCorrelationRuleRequest,
                        indexCorrelationRuleResponse(channel, request.method()));
    }

    private RestResponseListener<IndexCorrelationRuleResponse> indexCorrelationRuleResponse(
            RestChannel channel, RestRequest.Method restMethod) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(IndexCorrelationRuleResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;
                if (restMethod == RestRequest.Method.PUT) {
                    returnStatus = RestStatus.OK;
                }

                BytesRestResponse restResponse =
                        new BytesRestResponse(
                                returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));

                if (restMethod == RestRequest.Method.POST) {
                    String location =
                            String.format(
                                    Locale.ROOT,
                                    "%s/%s",
                                    SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI,
                                    response.getId());
                    restResponse.addHeader("Location", location);
                }

                return restResponse;
            }
        };
    }
}
