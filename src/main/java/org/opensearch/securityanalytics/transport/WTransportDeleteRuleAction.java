/*
 * Copyright (C) 2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package org.opensearch.securityanalytics.transport;

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

import com.wazuh.securityanalytics.action.WDeleteRuleAction;
import com.wazuh.securityanalytics.action.WDeleteRuleRequest;
import com.wazuh.securityanalytics.action.WDeleteRuleResponse;

public class WTransportDeleteRuleAction
        extends HandledTransportAction<WDeleteRuleRequest, WDeleteRuleResponse>
        implements SecureTransportAction {

    private final TransportDeleteRuleAction internalAction;

    @Inject
    public WTransportDeleteRuleAction(
            TransportService transportService,
            Client client,
            DetectorIndices detectorIndices,
            ActionFilters actionFilters,
            NamedXContentRegistry xContentRegistry) {
        super(WDeleteRuleAction.NAME, transportService, actionFilters, WDeleteRuleRequest::new);

        // Initialize the internal action configured for the PRE_PACKAGED_RULES_INDEX.
        this.internalAction =
                createInternalAction(
                        transportService, client, detectorIndices, actionFilters, xContentRegistry);
    }

    @Override
    protected void doExecute(
            Task task, WDeleteRuleRequest request, ActionListener<WDeleteRuleResponse> listener) {
        DeleteRuleRequest internalRequest =
                new DeleteRuleRequest(request.getRuleId(), request.getRefreshPolicy(), request.isForced());
        internalAction.doExecute(
                task,
                internalRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(DeleteRuleResponse response) {
                        log.info("Successfully deleted rule with id: {}", response.getId());
                        listener.onResponse(
                                new WDeleteRuleResponse(
                                        response.getId(), response.getVersion(), response.getStatus()));
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
     * <p>Method created to allow tests to mock the action
     */
    protected TransportDeleteRuleAction createInternalAction(
            TransportService transportService,
            Client client,
            DetectorIndices detectorIndices,
            ActionFilters actionFilters,
            NamedXContentRegistry xContentRegistry) {
        return new TransportDeleteRuleAction(
                WDeleteRuleAction.NAME + "/internal",
                transportService,
                client,
                detectorIndices,
                actionFilters,
                xContentRegistry,
                Rule.PRE_PACKAGED_RULES_INDEX);
    }
}
