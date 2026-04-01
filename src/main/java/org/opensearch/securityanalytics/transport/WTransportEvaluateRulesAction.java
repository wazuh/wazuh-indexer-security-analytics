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
import org.opensearch.securityanalytics.rules.engine.EventMatcher;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import com.wazuh.securityanalytics.action.WEvaluateRulesAction;
import com.wazuh.securityanalytics.action.WEvaluateRulesRequest;
import com.wazuh.securityanalytics.action.WEvaluateRulesResponse;

/**
 * Transport action handler for evaluating Sigma rules against a normalized event.
 *
 * @see WEvaluateRulesAction
 * @see EventMatcher
 */
public class WTransportEvaluateRulesAction
        extends HandledTransportAction<WEvaluateRulesRequest, WEvaluateRulesResponse> {

    private static final Logger log = LogManager.getLogger(WTransportEvaluateRulesAction.class);

    /**
     * Constructs a new WTransportEvaluateRulesAction.
     *
     * @param transportService the transport service
     * @param actionFilters the action filters
     */
    @Inject
    public WTransportEvaluateRulesAction(
            TransportService transportService, ActionFilters actionFilters) {
        super(WEvaluateRulesAction.NAME, transportService, actionFilters, WEvaluateRulesRequest::new);
    }

    @Override
    protected void doExecute(
            Task task, WEvaluateRulesRequest request, ActionListener<WEvaluateRulesResponse> listener) {
        try {
            String resultJson = EventMatcher.evaluate(request.getEventJson(), request.getRulesBodies());
            listener.onResponse(new WEvaluateRulesResponse(resultJson));
        } catch (Exception e) {
            log.error("Failed to evaluate Sigma rules against event.", e);
            listener.onFailure(e);
        }
    }
}
