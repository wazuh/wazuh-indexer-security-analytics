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
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.ListCorrelationsAction;
import org.opensearch.securityanalytics.action.ListCorrelationsRequest;
import org.opensearch.securityanalytics.action.ListCorrelationsResponse;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.core.rest.RestStatus.OK;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestListCorrelationAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestListCorrelationAction.class);

    @Override
    public String getName() {
        return "list_correlation_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, SecurityAnalyticsPlugin.LIST_CORRELATIONS_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        log.debug(
                String.format(
                        Locale.ROOT, "%s %s", request.method(), SecurityAnalyticsPlugin.LIST_CORRELATIONS_URI));

        long defaultTimestamp = System.currentTimeMillis();
        Long startTimestamp = request.paramAsLong("start_timestamp", defaultTimestamp - 300000L);
        Long endTimestamp = request.paramAsLong("end_timestamp", defaultTimestamp);

        ListCorrelationsRequest correlationsRequest =
                new ListCorrelationsRequest(startTimestamp, endTimestamp);
        return channel -> {
            client.execute(
                    ListCorrelationsAction.INSTANCE,
                    correlationsRequest,
                    new RestListCorrelationAction.RestListCorrelationResponseListener(channel, request));
        };
    }

    static class RestListCorrelationResponseListener
            extends RestResponseListener<ListCorrelationsResponse> {
        private final RestRequest request;

        RestListCorrelationResponseListener(RestChannel channel, RestRequest request) {
            super(channel);
            this.request = request;
        }

        @Override
        public RestResponse buildResponse(final ListCorrelationsResponse response) throws Exception {
            return new BytesRestResponse(
                    OK, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
        }
    }
}
