/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WDeleteCustomRuleAction;
import com.wazuh.securityanalytics.action.WDeleteCustomRuleRequest;
import com.wazuh.securityanalytics.action.WDeleteRuleResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.action.DeleteRuleAction;
import org.opensearch.securityanalytics.action.DeleteRuleRequest;
import org.opensearch.securityanalytics.action.DeleteRuleResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

public class WTransportDeleteCustomRuleAction extends HandledTransportAction<WDeleteCustomRuleRequest, WDeleteRuleResponse>
    implements
        SecureTransportAction {

    private static final Logger log = LogManager.getLogger(WTransportDeleteCustomRuleAction.class);
    private final Client client;

    @Inject
    public WTransportDeleteCustomRuleAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(WDeleteCustomRuleAction.NAME, transportService, actionFilters, WDeleteCustomRuleRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, WDeleteCustomRuleRequest request, ActionListener<WDeleteRuleResponse> listener) {
        DeleteRuleRequest internalRequest = new DeleteRuleRequest(request.getRuleId(), request.getRefreshPolicy(), request.isForced());

        // Delegate to the default action
        this.client.execute(DeleteRuleAction.INSTANCE, internalRequest, new ActionListener<DeleteRuleResponse>() {
            @Override
            public void onResponse(DeleteRuleResponse response) {
                log.info("Successfully deleted custom rule with id: {}", response.getId());
                listener.onResponse(new WDeleteRuleResponse(response.getId(), response.getVersion(), response.getStatus()));
            }

            @Override
            public void onFailure(Exception e) {
                log.error("Failed to delete custom rule via default action: {}", e.getMessage());
                listener.onFailure(e);
            }
        });
    }
}
