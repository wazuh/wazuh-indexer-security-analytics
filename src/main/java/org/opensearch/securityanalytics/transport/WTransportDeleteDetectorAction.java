/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WDeleteDetectorAction;
import com.wazuh.securityanalytics.action.WDeleteDetectorRequest;
import com.wazuh.securityanalytics.action.WDeleteDetectorResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.action.DeleteDetectorAction;
import org.opensearch.securityanalytics.action.DeleteDetectorRequest;
import org.opensearch.securityanalytics.action.DeleteDetectorResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

public class WTransportDeleteDetectorAction extends HandledTransportAction<WDeleteDetectorRequest, WDeleteDetectorResponse> implements SecureTransportAction {
    private final Client client;
    private static final Logger log = LogManager.getLogger(WTransportDeleteDetectorAction.class);

    @Inject
    public WTransportDeleteDetectorAction(TransportService transportService,
                                          Client client,
                                          ActionFilters actionFilters) {
        super(WDeleteDetectorAction.NAME, transportService, actionFilters, WDeleteDetectorRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, WDeleteDetectorRequest request, ActionListener<WDeleteDetectorResponse> listener) {
        DeleteDetectorRequest internalRequest = new DeleteDetectorRequest(
                request.getDetectorId(),
                request.getRefreshPolicy()
        );
        this.client.execute(DeleteDetectorAction.INSTANCE, internalRequest, new ActionListener<DeleteDetectorResponse>() {
            @Override
            public void onResponse(DeleteDetectorResponse response) {
                log.info("Successfully deleted detector with id: " + response.getId());
                listener.onResponse(new WDeleteDetectorResponse(response.getId(), response.getVersion(), response.getStatus()));
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }
}