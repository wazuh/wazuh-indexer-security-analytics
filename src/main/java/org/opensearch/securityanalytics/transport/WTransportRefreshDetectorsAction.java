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
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.util.RuleDetectorSync;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import com.wazuh.securityanalytics.action.WRefreshDetectorsAction;
import com.wazuh.securityanalytics.action.WRefreshDetectorsRequest;
import com.wazuh.securityanalytics.action.WRefreshDetectorsResponse;

/**
 * Transport action that rebuilds, once each, the detectors referencing any of the given rules.
 *
 * <p>A rebuild re-indexes the detector, which recompiles its existing monitor from the rules'
 * stored queries: no monitor and no query index is added.
 *
 * @see WRefreshDetectorsAction
 * @see RuleDetectorSync#rebuildDetectorsForRules
 */
public class WTransportRefreshDetectorsAction
        extends HandledTransportAction<WRefreshDetectorsRequest, WRefreshDetectorsResponse> {

    private final Client client;
    private final NamedXContentRegistry xContentRegistry;
    private final ThreadPool threadPool;

    /**
     * Constructs a new WTransportRefreshDetectorsAction.
     *
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param client the OpenSearch client
     * @param xContentRegistry registry used to parse detector documents
     * @param threadPool the thread pool, used to rebuild the detectors as the plugin
     */
    @Inject
    public WTransportRefreshDetectorsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            NamedXContentRegistry xContentRegistry,
            ThreadPool threadPool) {
        super(
                WRefreshDetectorsAction.NAME,
                transportService,
                actionFilters,
                WRefreshDetectorsRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(
            Task task,
            WRefreshDetectorsRequest request,
            ActionListener<WRefreshDetectorsResponse> listener) {
        // Detectors belong to the plugin, as when a rule change rebuilds them.
        this.threadPool.getThreadContext().stashContext();
        RuleDetectorSync.rebuildDetectorsForRules(
                this.client,
                this.xContentRegistry,
                request.getRuleIds(),
                WriteRequest.RefreshPolicy.IMMEDIATE,
                ActionListener.wrap(
                        rebuilt -> listener.onResponse(new WRefreshDetectorsResponse(rebuilt)),
                        listener::onFailure));
    }
}
