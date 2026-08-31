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
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.util.DetectorUtils;
import org.opensearch.securityanalytics.util.RegistryOverrideWriter;
import org.opensearch.securityanalytics.util.RestHandlerUtils;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.time.Instant;
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
                new Route(
                        RestRequest.Method.PUT,
                        String.format(
                                Locale.getDefault(),
                                "%s/{%s}",
                                SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
                                DetectorUtils.DETECTOR_ID_FIELD)));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        log.debug(
                String.format(
                        Locale.getDefault(),
                        "%s %s",
                        request.method(),
                        SecurityAnalyticsPlugin.DETECTOR_BASE_URI));

        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.IMMEDIATE;
        if (request.hasParam(RestHandlerUtils.REFRESH)) {
            refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(RestHandlerUtils.REFRESH));
        }

        String id = request.param("detector_id", Detector.NO_ID);

        XContentParser xcp = request.contentParser();
        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);

        Detector detector = Detector.parse(xcp, id, null);
        detector.setLastUpdateTime(Instant.now());
        validateDetectorTriggers(detector);

        IndexDetectorRequest indexDetectorRequest =
                new IndexDetectorRequest(id, refreshPolicy, request.method(), detector);
        return channel ->
                client.execute(
                        IndexDetectorAction.INSTANCE,
                        indexDetectorRequest,
                        indexDetectorResponse(channel, request.method(), client));
    }

    private static void validateDetectorTriggers(Detector detector) {
        if (detector.getTriggers() != null) {
            for (DetectorTrigger trigger : detector.getTriggers()) {
                if (trigger.getDetectionTypes().isEmpty())
                    throw new IllegalArgumentException(
                            String.format(
                                    Locale.ROOT,
                                    "Trigger [%s] should mention at least one detection type but found none",
                                    trigger.getName()));
                for (String detectionType : trigger.getDetectionTypes()) {
                    if (false
                            == (DetectorTrigger.THREAT_INTEL_DETECTION_TYPE.equals(detectionType)
                                    || DetectorTrigger.RULES_DETECTION_TYPE.equals(detectionType))) {
                        throw new IllegalArgumentException(
                                String.format(
                                        Locale.ROOT,
                                        "Trigger [%s] has unsupported detection type [%s]",
                                        trigger.getName(),
                                        detectionType));
                    }
                }
            }
        }
    }

    private RestResponseListener<IndexDetectorResponse> indexDetectorResponse(
            RestChannel channel, RestRequest.Method restMethod, NodeClient client) {
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
                RegistryOverrideWriter.recordDetectorEnabled(
                        client, response.getId(), response.getDetector());

                BytesRestResponse restResponse =
                        new BytesRestResponse(
                                returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));

                if (restMethod == RestRequest.Method.POST) {
                    String location =
                            String.format(
                                    Locale.getDefault(),
                                    "%s/%s",
                                    SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
                                    response.getId());
                    restResponse.addHeader("Location", location);
                }

                return restResponse;
            }
        };
    }
}
