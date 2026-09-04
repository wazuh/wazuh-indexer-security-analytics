/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.DetectorUtils;
import org.opensearch.securityanalytics.util.RegistryOverrideWriter;
import org.opensearch.securityanalytics.util.RestHandlerUtils;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

public class RestIndexDetectorAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestIndexDetectorAction.class);

    @Override
    public String getName() {
        return "index_detector_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.DETECTOR_BASE_URI),
                new Route(RestRequest.Method.PUT, String.format(Locale.getDefault(),
                        "%s/{%s}",
                        SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
                        DetectorUtils.DETECTOR_ID_FIELD))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.DETECTOR_BASE_URI));

        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.IMMEDIATE;
        if (request.hasParam(RestHandlerUtils.REFRESH)) {
            refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(RestHandlerUtils.REFRESH));
        }

        String id = request.param("detector_id", Detector.NO_ID);

        // Forwarded verbatim and parsed by TransportIndexDetectorAction. Privileges are evaluated in
        // the transport ActionFilters chain, which runs after every REST handler, so parsing here
        // exposed the whole parsing path to accounts the same request, well-formed, refuses with 403.
        byte[] body = request.hasContent() ? request.content().streamInput().readAllBytes() : null;
        String mediaType = request.getMediaType() != null ? request.getMediaType().mediaTypeWithoutParameters() : null;

        IndexDetectorRequest indexDetectorRequest = new IndexDetectorRequest(id, refreshPolicy, request.method(), body, mediaType);
        return channel -> client.execute(IndexDetectorAction.INSTANCE, indexDetectorRequest, indexDetectorResponse(channel, request.method(), client));
    }

    private RestResponseListener<IndexDetectorResponse> indexDetectorResponse(RestChannel channel, RestRequest.Method restMethod, NodeClient client) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(IndexDetectorResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;
                if (restMethod == RestRequest.Method.PUT) {
                    returnStatus = RestStatus.OK;
                }

                // Only a user's own change reaches this handler: Content Manager drives detectors over
                // transport, which never runs a REST handler. So a standard detector saved here is the
                // user starting or stopping it, and that choice must outlive the next content rebuild.
                //
                // The detector from the response, not the one parsed from the request: a toggle sends
                // only the fields the client happened to hold, and the transport action restores the
                // rest -- including `source` -- from the stored document.
                RegistryOverrideWriter.recordDetectorEnabled(client, response.getId(), response.getDetector());

                BytesRestResponse restResponse = new BytesRestResponse(returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));

                if (restMethod == RestRequest.Method.POST) {
                    String location = String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, response.getId());
                    restResponse.addHeader("Location", location);
                }

                return restResponse;
            }
        };
    }
}