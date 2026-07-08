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
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.time.Instant;

import com.wazuh.securityanalytics.action.WSetDetectorEnabledAction;
import com.wazuh.securityanalytics.action.WSetDetectorEnabledRequest;
import com.wazuh.securityanalytics.action.WSetDetectorEnabledResponse;

/**
 * Toggles the {@code enabled} state of an existing detector without changing anything else.
 *
 * <p>The detector is fetched by id, only its {@code enabled} (and derived {@code
 * enabledTime}/{@code lastUpdateTime}) is changed, and it is re-indexed through the normal update
 * path as an internal caller.
 */
public class WTransportSetDetectorEnabledAction
        extends HandledTransportAction<WSetDetectorEnabledRequest, WSetDetectorEnabledResponse> {

    private static final Logger log = LogManager.getLogger(WTransportSetDetectorEnabledAction.class);
    private final Client client;
    private final NamedXContentRegistry xContentRegistry;

    @Inject
    public WTransportSetDetectorEnabledAction(
            TransportService transportService,
            Client client,
            ActionFilters actionFilters,
            NamedXContentRegistry xContentRegistry) {
        super(
                WSetDetectorEnabledAction.NAME,
                transportService,
                actionFilters,
                WSetDetectorEnabledRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
    }

    @Override
    protected void doExecute(
            Task task,
            WSetDetectorEnabledRequest request,
            ActionListener<WSetDetectorEnabledResponse> listener) {
        String detectorId = request.getDetectorId();
        GetRequest getRequest = new GetRequest(Detector.DETECTORS_INDEX, detectorId);

        this.client.get(
                getRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetResponse response) {
                        if (!response.isExists()) {
                            // No detector for this integration; nothing to toggle.
                            log.debug("No detector found with id [{}]; nothing to toggle.", detectorId);
                            listener.onResponse(new WSetDetectorEnabledResponse(detectorId, -1L, RestStatus.OK));
                            return;
                        }

                        try {
                            XContentParser xcp =
                                    XContentHelper.createParser(
                                            WTransportSetDetectorEnabledAction.this.xContentRegistry,
                                            LoggingDeprecationHandler.INSTANCE,
                                            response.getSourceAsBytesRef(),
                                            XContentType.JSON);
                            Detector detector = Detector.docParse(xcp, detectorId, response.getVersion());

                            // Idempotent: skip the re-index if the state already matches.
                            if (detector.getEnabled() != null && detector.getEnabled() == request.isEnabled()) {
                                listener.onResponse(
                                        new WSetDetectorEnabledResponse(
                                                detectorId, response.getVersion(), RestStatus.OK));
                                return;
                            }

                            boolean enabled = request.isEnabled();
                            detector.setEnabled(enabled);
                            detector.setEnabledTime(enabled ? Instant.now() : null);
                            detector.setLastUpdateTime(Instant.now());

                            IndexDetectorRequest indexRequest =
                                    new IndexDetectorRequest(
                                            detectorId,
                                            request.getRefreshPolicy(),
                                            RestRequest.Method.PUT,
                                            detector,
                                            true);

                            WTransportSetDetectorEnabledAction.this.client.execute(
                                    IndexDetectorAction.INSTANCE,
                                    indexRequest,
                                    new ActionListener<IndexDetectorResponse>() {
                                        @Override
                                        public void onResponse(IndexDetectorResponse indexResponse) {
                                            log.debug("Detector [{}] enabled set to {}.", detectorId, enabled);
                                            listener.onResponse(
                                                    new WSetDetectorEnabledResponse(
                                                            indexResponse.getId(),
                                                            indexResponse.getVersion(),
                                                            indexResponse.getStatus()));
                                        }

                                        @Override
                                        public void onFailure(Exception e) {
                                            listener.onFailure(e);
                                        }
                                    });
                        } catch (Exception e) {
                            listener.onFailure(e);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
    }
}
