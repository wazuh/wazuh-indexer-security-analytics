/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import static org.opensearch.securityanalytics.logtype.LogTypeService.LOG_TYPE_INDEX;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import com.wazuh.securityanalytics.action.WIndexIntegrationAction;
import com.wazuh.securityanalytics.action.WIndexIntegrationRequest;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;
import com.wazuh.securityanalytics.model.Integration;

public class WTransportIndexIntegrationAction extends HandledTransportAction<WIndexIntegrationRequest, WIndexIntegrationResponse> implements SecureTransportAction {
    private final Client client;
    private static final Logger log = LogManager.getLogger(WTransportIndexIntegrationAction.class);

    @Inject
    public WTransportIndexIntegrationAction(TransportService transportService,
                                            Client client,
                                            ActionFilters actionFilters) {
        super(WIndexIntegrationAction.NAME, transportService, actionFilters, WIndexIntegrationRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, WIndexIntegrationRequest request, ActionListener<WIndexIntegrationResponse> listener) {
        Integration integration = request.getCustomLogType();
        try {
            IndexRequest indexRequest = new IndexRequest()
                    .index(LOG_TYPE_INDEX)
                    .id(request.getLogTypeId())
                    .source(integration.toXContent());

            this.client.index(indexRequest, ActionListener.wrap(
                    indexResponse -> {
                        WIndexIntegrationResponse response = new WIndexIntegrationResponse(
                                integration.getId(),
                                integration.getVersion(),
                                indexResponse.status(),
                                integration);
                        listener.onResponse(response);
                    }, exception -> {
                        log.error("Error indexing Wazuh integration: ", exception);
                        listener.onFailure(exception);
                    }));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
