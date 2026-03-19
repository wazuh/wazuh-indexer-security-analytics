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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.action.IndexRuleAction;
import org.opensearch.securityanalytics.action.IndexRuleRequest;
import org.opensearch.securityanalytics.action.IndexRuleResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import com.wazuh.securityanalytics.action.WIndexCustomRuleAction;
import com.wazuh.securityanalytics.action.WIndexCustomRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;

public class WTransportIndexCustomRuleAction
        extends HandledTransportAction<WIndexCustomRuleRequest, WIndexRuleResponse>
        implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(WTransportIndexCustomRuleAction.class);

    private final Client client;

    @Inject
    public WTransportIndexCustomRuleAction(
            TransportService transportService, Client client, ActionFilters actionFilters) {
        super(
                WIndexCustomRuleAction.NAME, transportService, actionFilters, WIndexCustomRuleRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(
            Task task, WIndexCustomRuleRequest request, ActionListener<WIndexRuleResponse> listener) {
        IndexRuleRequest internalRequest =
                new IndexRuleRequest(
                        request.getRuleId(),
                        request.getRefreshPolicy(),
                        request.getLogType(),
                        request.getMethod(),
                        request.getRule(),
                        request.isForced());
        this.client.execute(
                IndexRuleAction.INSTANCE,
                internalRequest,
                new ActionListener<IndexRuleResponse>() {
                    @Override
                    public void onResponse(IndexRuleResponse response) {
                        log.info("Successfully indexed custom rule with id: " + response.getId());
                        listener.onResponse(
                                new WIndexRuleResponse(
                                        response.getId(), response.getVersion(), response.getStatus()));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to index custom rule via default action: {}", e.getMessage());
                        listener.onFailure(e);
                    }
                });
    }
}
