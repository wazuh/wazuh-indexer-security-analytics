/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WIndexCustomRuleAction;
import com.wazuh.securityanalytics.action.WIndexCustomRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.action.IndexRuleRequest;
import org.opensearch.securityanalytics.action.IndexRuleResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class WTransportIndexCustomRuleAction extends HandledTransportAction<WIndexCustomRuleRequest, WIndexRuleResponse>
        implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(WTransportIndexCustomRuleAction.class);
    private final TransportIndexRuleAction transportIndexRuleAction;

    @Inject
    public WTransportIndexCustomRuleAction(
            TransportService transportService,
            ActionFilters actionFilters,
            TransportIndexRuleAction transportIndexRuleAction
    ) {
        super(WIndexCustomRuleAction.NAME, transportService, actionFilters, WIndexCustomRuleRequest::new);
        this.transportIndexRuleAction = transportIndexRuleAction;
    }

    @Override
    protected void doExecute(Task task, WIndexCustomRuleRequest request, ActionListener<WIndexRuleResponse> listener) {
        IndexRuleRequest internalRequest = new IndexRuleRequest(
                request.getRuleId(),
                request.getRefreshPolicy(),
                request.getLogType(),
                request.getMethod(),
                request.getRule(),
                request.isForced()
        );

        // Delegate to the default action
        this.transportIndexRuleAction.execute(internalRequest, new ActionListener<>() {
            @Override
            public void onResponse(IndexRuleResponse response) {
                log.info("Successfully indexed custom rule with id: {}", response.getId());
                listener.onResponse(new WIndexRuleResponse(response.getId(), response.getVersion(), response.getStatus()));
            }

            @Override
            public void onFailure(Exception e) {
                log.error("Failed to index custom rule via default action: {}", e.getMessage());
                listener.onFailure(e);
            }
        });
    }
}