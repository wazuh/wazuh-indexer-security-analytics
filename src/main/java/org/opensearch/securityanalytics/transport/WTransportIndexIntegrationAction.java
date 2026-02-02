/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import java.io.IOException;
import java.util.Objects;

import com.wazuh.securityanalytics.action.WIndexIntegrationAction;
import com.wazuh.securityanalytics.action.WIndexIntegrationRequest;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;
import com.wazuh.securityanalytics.model.Integration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeAction;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeRequest;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeResponse;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import static org.opensearch.securityanalytics.logtype.LogTypeService.LOG_TYPE_INDEX;

/**
 * Transport action for indexing Wazuh integrations (log types) into the Security Analytics log type
 * index. This action handles the storage of integration definitions that describe how different log
 * sources are processed and analyzed.
 *
 * <p>Integrations define log type configurations including metadata such as name, description,
 * category, source, tags, and associated rule IDs. This action persists these configurations to
 * enable the Security Analytics plugin to process logs from various sources.
 *
 * <p>The action implements {@link SecureTransportAction} to ensure proper security context
 * handling during execution. Indexing is performed with immediate refresh to ensure the
 * integration is available for use promptly after creation.
 */
public class WTransportIndexIntegrationAction extends HandledTransportAction<WIndexIntegrationRequest, WIndexIntegrationResponse>
        implements
        SecureTransportAction {
    /**
     * OpenSearch client for executing index operations.
     */
    private final Client client;

    /**
     * Logger instance for the WTransportIndexIntegrationAction class.
     */
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
     * Executes the integration indexing action. This method persists a Wazuh integration
     * configuration to the Security Analytics log type index.
     *
     * <p>On success, returns a {@link WIndexIntegrationResponse} containing the integration ID,
     * version, status, and the full integration object. On failure, logs the error and notifies
     * the listener with the exception.
     *
     * @param task     The task associated with this action execution.
     * @param request  The integration indexing request containing the Integration data.
     * @param listener The listener to notify upon completion or failure.
     */
    @Override
    protected void doExecute(Task task, WIndexIntegrationRequest request, ActionListener<WIndexIntegrationResponse> listener) {
        Integration integration = request.getIntegration();

        // Custom integration / log type.
        if (!Objects.equals(integration.getSource(), "Sigma")) {
            try {
                IndexCustomLogTypeRequest internalRequest = new IndexCustomLogTypeRequest(
                        integration.getId(),
                        WriteRequest.RefreshPolicy.IMMEDIATE,
                        RestRequest.Method.POST,
                        new CustomLogType(
                                integration.getId(),
                                integration.getVersion(),
                                integration.getName(),
                                integration.getCategory(),
                                integration.getSource(),
                                integration.getSource(),
                                integration.getTags())
                );
                this.client.execute(IndexCustomLogTypeAction.INSTANCE, internalRequest, new ActionListener<IndexCustomLogTypeResponse>() {
                    @Override
                    public void onResponse(IndexCustomLogTypeResponse response) {
                        log.info("Successfully indexed custom integration with id: {}", response.getId());
                        listener.onResponse(new WIndexIntegrationResponse(response.getId(), response.getVersion(), response.getStatus(), integration));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to index custom integration via default action: {}", e.getMessage());
                        listener.onFailure(e);
                    }
                });
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            // Standard integrations
            try {
                IndexRequest indexRequest = new IndexRequest().index(LOG_TYPE_INDEX)
                        .id(request.getId())
                        .source(integration.toXContent());

                this.client.index(indexRequest, ActionListener.wrap(indexResponse -> {
                    WIndexIntegrationResponse response = new WIndexIntegrationResponse(
                            integration.getId(),
                            integration.getVersion(),
                            indexResponse.status(),
                            integration
                    );
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
}
