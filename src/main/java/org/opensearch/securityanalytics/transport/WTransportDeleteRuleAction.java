/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WDeleteRuleAction;
import com.wazuh.securityanalytics.action.WDeleteRuleRequest;
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

public class WTransportDeleteRuleAction extends HandledTransportAction<WDeleteRuleRequest, WDeleteRuleResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(WTransportDeleteRuleAction.class);

    private final Client client;

    @Inject
    public WTransportDeleteRuleAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(WDeleteRuleAction.NAME, transportService, actionFilters, WDeleteRuleRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, WDeleteRuleRequest request, ActionListener<WDeleteRuleResponse> listener) {
        DeleteRuleRequest internalRequest = new DeleteRuleRequest(
                request.getRuleId(),
                request.getRefreshPolicy(),
                request.isForced()
        );
        this.client.execute(DeleteRuleAction.INSTANCE, internalRequest, new ActionListener<DeleteRuleResponse>() {
            @Override
            public void onResponse(DeleteRuleResponse response) {
                log.info("Successfully deleted rule with id: " + response.getId());
                listener.onResponse(new WDeleteRuleResponse(response.getId(), response.getVersion(), response.getStatus()));
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }
}