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

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsAction;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsRequest;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;

public class TransportUpdateIndexMappingsAction
        extends HandledTransportAction<UpdateIndexMappingsRequest, AcknowledgedResponse> {

    private MapperService mapperService;
    private ClusterService clusterService;

    private final ThreadPool threadPool;

    @Inject
    public TransportUpdateIndexMappingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            ThreadPool threadPool,
            MapperService mapperService,
            ClusterService clusterService) {
        super(
                UpdateIndexMappingsAction.NAME,
                transportService,
                actionFilters,
                UpdateIndexMappingsRequest::new);
        this.clusterService = clusterService;
        this.mapperService = mapperService;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(
            Task task,
            UpdateIndexMappingsRequest request,
            ActionListener<AcknowledgedResponse> actionListener) {
        this.threadPool.getThreadContext().stashContext();
        try {
            IndexMetadata index = clusterService.state().metadata().index(request.getIndexName());
            if (index == null) {
                actionListener.onFailure(
                        SecurityAnalyticsException.wrap(
                                new OpenSearchStatusException(
                                        "Could not find index [" + request.getIndexName() + "]",
                                        RestStatus.NOT_FOUND)));
                return;
            }
            mapperService.updateMappingAction(
                    request.getIndexName(),
                    request.getAlias(),
                    buildAliasJson(request.getField()),
                    actionListener);
        } catch (IOException e) {
            actionListener.onFailure(e);
        }
    }

    private String buildAliasJson(String fieldName) throws IOException {
        return "type=alias,path=" + fieldName;
    }
}
