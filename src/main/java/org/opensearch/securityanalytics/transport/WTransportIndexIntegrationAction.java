/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WIndexIntegrationAction;
import com.wazuh.securityanalytics.action.WIndexIntegrationRequest;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeAction;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeRequest;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

public class WTransportIndexIntegrationAction extends HandledTransportAction<WIndexIntegrationRequest, WIndexIntegrationResponse> implements SecureTransportAction {
    private final Client client;

    @Inject
    public WTransportIndexIntegrationAction(TransportService transportService,
                                            Client client,
                                            ActionFilters actionFilters) {
        super(WIndexIntegrationAction.NAME, transportService, actionFilters, WIndexIntegrationRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, WIndexIntegrationRequest request, ActionListener<WIndexIntegrationResponse> listener) {
        IndexCustomLogTypeRequest internalRequest = new IndexCustomLogTypeRequest(
                request.getLogTypeId(),
                WriteRequest.RefreshPolicy.IMMEDIATE,
                request.getMethod(),
                new CustomLogType(
                        request.getCustomLogType().getId(),
                        request.getCustomLogType().getVersion(),
                        request.getCustomLogType().getName(),
                        request.getCustomLogType().getDescription(),
                        request.getCustomLogType().getCategory(),
                        request.getCustomLogType().getSource(),
                        request.getCustomLogType().getTags()
                )
        );

        this.client.execute(IndexCustomLogTypeAction.INSTANCE, internalRequest);
    }
}