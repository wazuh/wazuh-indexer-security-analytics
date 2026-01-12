/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WDeleteRuleAction;
import com.wazuh.securityanalytics.action.WDeleteRuleRequest;
import com.wazuh.securityanalytics.action.WDeleteRuleResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.action.DeleteRuleRequest;
import org.opensearch.securityanalytics.action.DeleteRuleResponse;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

public class WTransportDeleteRuleAction extends HandledTransportAction<WDeleteRuleRequest, WDeleteRuleResponse> implements SecureTransportAction {

    private final TransportDeleteRuleAction internalAction;

    @Inject
    public WTransportDeleteRuleAction(TransportService transportService, Client client, DetectorIndices detectorIndices, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry) {
        super(WDeleteRuleAction.NAME, transportService, actionFilters, WDeleteRuleRequest::new);

        // Initialize the internal action configured for the PRE_PACKAGED_RULES_INDEX.
        this.internalAction = createInternalAction(transportService, client, detectorIndices, actionFilters, xContentRegistry);
    }

    @Override
    protected void doExecute(Task task, WDeleteRuleRequest request, ActionListener<WDeleteRuleResponse> listener) {
        DeleteRuleRequest internalRequest = new DeleteRuleRequest(
                request.getRuleId(),
                request.getRefreshPolicy(),
                request.isForced()
        );
        internalAction.doExecute(task, internalRequest, new ActionListener<>() {
            @Override
            public void onResponse(DeleteRuleResponse response) {
                log.info("Successfully deleted rule with id: {}", response.getId());
                listener.onResponse(new WDeleteRuleResponse(response.getId(), response.getVersion(), response.getStatus()));
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    /**
     * Creates the internal action using the PRE_PACKAGED_RULES_INDEX to allow deletion of Wazuh rules
     *
     * Method created to allow tests to mock the action
     */
    protected TransportDeleteRuleAction createInternalAction(TransportService transportService, Client client, DetectorIndices detectorIndices, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry){
        return new TransportDeleteRuleAction(
                WDeleteRuleAction.NAME + "/internal",
                transportService,
                client,
                detectorIndices,
                actionFilters,
                xContentRegistry,
                Rule.PRE_PACKAGED_RULES_INDEX
        );
    }

}