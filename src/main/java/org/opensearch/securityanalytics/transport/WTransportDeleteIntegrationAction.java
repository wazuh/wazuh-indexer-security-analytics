/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WDeleteIntegrationAction;
import com.wazuh.securityanalytics.action.WDeleteIntegrationRequest;
import com.wazuh.securityanalytics.action.WDeleteIntegrationResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeAction;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeRequest;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

public class WTransportDeleteIntegrationAction extends HandledTransportAction<WDeleteIntegrationRequest, WDeleteIntegrationResponse>
    implements
        SecureTransportAction {
    private final Client client;
    private static final Logger log = LogManager.getLogger(WTransportDeleteIntegrationAction.class);

    @Inject
    public WTransportDeleteIntegrationAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(WDeleteIntegrationAction.NAME, transportService, actionFilters, WDeleteIntegrationRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, WDeleteIntegrationRequest request, ActionListener<WDeleteIntegrationResponse> listener) {
        DeleteCustomLogTypeRequest internalRequest = new DeleteCustomLogTypeRequest(request.getLogTypeId(), request.getRefreshPolicy());
        this.client.execute(DeleteCustomLogTypeAction.INSTANCE, internalRequest, new ActionListener<DeleteCustomLogTypeResponse>() {
            @Override
            public void onResponse(DeleteCustomLogTypeResponse response) {
                log.info("Successfully deleted integration with id: " + response.getId());
                listener.onResponse(new WDeleteIntegrationResponse(response.getId(), response.getVersion(), response.getStatus()));
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }
}
