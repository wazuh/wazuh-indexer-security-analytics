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
<<<<<<< HEAD

=======
import org.opensearch.action.index.IndexRequest;
>>>>>>> main
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
<<<<<<< HEAD
import org.opensearch.securityanalytics.action.IndexCustomLogTypeAction;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeRequest;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeResponse;
import org.opensearch.securityanalytics.model.CustomLogType;
=======
import static org.opensearch.securityanalytics.logtype.LogTypeService.LOG_TYPE_INDEX;
>>>>>>> main
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

<<<<<<< HEAD
// TODO: Update description when merged with Standard LogType creation
/**
 * Transport action handler for indexing Wazuh integrations.
 * This class handles the transport-level execution of integration indexing requests,
 * converting external {@link WIndexIntegrationRequest} objects into internal
 * {@link IndexCustomLogTypeRequest} objects and delegating to the standard custom log type indexing action.
 * The action uses {@link CustomLogType} to create custom log type instances from the provided
 * log type data before persisting them.
 * @see WIndexIntegrationAction
 * @see WIndexIntegrationRequest
 * @see WIndexIntegrationResponse
 * @see CustomLogType
 */
public class WTransportIndexIntegrationAction extends HandledTransportAction<WIndexIntegrationRequest, WIndexIntegrationResponse>
    implements
        SecureTransportAction {
=======
import com.wazuh.securityanalytics.action.WIndexIntegrationAction;
import com.wazuh.securityanalytics.action.WIndexIntegrationRequest;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;
import com.wazuh.securityanalytics.model.Integration;

public class WTransportIndexIntegrationAction extends HandledTransportAction<WIndexIntegrationRequest, WIndexIntegrationResponse> implements SecureTransportAction {
>>>>>>> main
    private final Client client;
    private static final Logger log = LogManager.getLogger(WTransportIndexIntegrationAction.class);

    /**
     * Constructs a new WTransportIndexIntegrationAction.
     *
     * @param transportService the transport service for inter-node communication
     * @param client           the OpenSearch client for executing internal actions
     * @param actionFilters    filters to apply to the action execution
     */
    @Inject
    public WTransportIndexIntegrationAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(WIndexIntegrationAction.NAME, transportService, actionFilters, WIndexIntegrationRequest::new);
        this.client = client;
    }

    /**
     * Executes the integration indexing action.
     *
     * This method performs the following steps:
     * 1. Extracts the custom log type data from the incoming request
     * 2. Creates a new {@link CustomLogType} instance with the extracted data
     * 3. Wraps it in an {@link IndexCustomLogTypeRequest} with IMMEDIATE refresh policy
     * 4. Executes the indexing action through the client
     * 5. Returns the result via the provided listener
     *
     * @param task     the task associated with this action execution
     * @param request  the integration indexing request containing the log type data
     * @param listener the listener to notify upon completion or failure
     */
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
