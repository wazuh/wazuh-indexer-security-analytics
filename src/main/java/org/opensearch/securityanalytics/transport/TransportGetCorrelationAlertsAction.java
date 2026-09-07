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
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.action.GetCorrelationAlertsAction;
import org.opensearch.securityanalytics.action.GetCorrelationAlertsRequest;
import org.opensearch.securityanalytics.action.GetCorrelationAlertsResponse;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportGetCorrelationAlertsAction
        extends HandledTransportAction<GetCorrelationAlertsRequest, GetCorrelationAlertsResponse>
        implements SecureTransportAction {

    private final NamedXContentRegistry xContentRegistry;

    private final ClusterService clusterService;

    private final Settings settings;

    private final ThreadPool threadPool;

    private final CorrelationAlertService correlationAlertService;

    private volatile Boolean filterByEnabled;

    private static final Logger log = LogManager.getLogger(TransportGetCorrelationAlertsAction.class);

    @Inject
    public TransportGetCorrelationAlertsAction(
            TransportService transportService,
            CorrelationAlertService correlationAlertService,
            ActionFilters actionFilters,
            ClusterService clusterService,
            GetCorrelationAlertsAction getCorrelationAlertsAction,
            ThreadPool threadPool,
            Settings settings,
            NamedXContentRegistry xContentRegistry) {
        super(
                getCorrelationAlertsAction.NAME,
                transportService,
                actionFilters,
                GetCorrelationAlertsRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.correlationAlertService = correlationAlertService;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(
            Task task,
            GetCorrelationAlertsRequest request,
            ActionListener<GetCorrelationAlertsResponse> actionListener) {

        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!validateBackendRoleMessage.isEmpty()) {
            actionListener.onFailure(
                    new OpenSearchStatusException(
                            "Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }

        this.threadPool.getThreadContext().stashContext();

        if (request.getCorrelationRuleId() != null) {
            correlationAlertService.getCorrelationAlerts(
                    request.getCorrelationRuleId(), request.getTable(), actionListener);
        } else {
            correlationAlertService.getCorrelationAlerts(null, request.getTable(), actionListener);
        }
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}
