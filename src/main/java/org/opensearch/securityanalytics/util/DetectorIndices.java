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
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.health.ClusterIndexHealth;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.maxSystemIndexReplicas;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.minSystemIndexReplicas;

public class DetectorIndices {

    private static final Logger log = LogManager.getLogger(DetectorIndices.class);

    private final AdminClient client;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    public DetectorIndices(AdminClient client, ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    public static String detectorMappings() throws IOException {
        return new String(
                Objects.requireNonNull(
                                DetectorIndices.class
                                        .getClassLoader()
                                        .getResourceAsStream("mappings/detectors.json"))
                        .readAllBytes(),
                Charset.defaultCharset());
    }

    /**
     * Builds the query selecting the detectors of a log type within one space. A detector references
     * its log type by name, and {@code source} is the only notion of space it carries: it is {@code
     * standard} for the detector of a standard integration and {@code custom} for a detector a user
     * created, so draft and test match nothing.
     */
    public static QueryBuilder detectorsByLogTypeAndSpace(String logTypeName, String space) {
        return QueryBuilders.nestedQuery(
                "detector",
                QueryBuilders.boolQuery()
                        .must(QueryBuilders.matchQuery("detector.detector_type", logTypeName))
                        .filter(QueryBuilders.termQuery("detector." + Detector.SOURCE_FIELD, space)),
                ScoreMode.Avg);
    }

    public void initDetectorIndex(ActionListener<CreateIndexResponse> actionListener)
            throws IOException {
        if (!detectorIndexExists()) {
            Settings indexSettings =
                    Settings.builder()
                            .put("index.hidden", true)
                            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                            .put(
                                    "index.auto_expand_replicas",
                                    minSystemIndexReplicas + "-" + maxSystemIndexReplicas)
                            .build();
            CreateIndexRequest indexRequest =
                    new CreateIndexRequest(Detector.DETECTORS_INDEX)
                            .mapping(detectorMappings())
                            .settings(indexSettings);
            client.indices().create(indexRequest, actionListener);
        }
    }

    public boolean detectorIndexExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(Detector.DETECTORS_INDEX);
    }

    public ClusterIndexHealth detectorIndexHealth() {
        ClusterIndexHealth indexHealth = null;

        if (detectorIndexExists()) {
            IndexRoutingTable indexRoutingTable =
                    clusterService.state().routingTable().index(Detector.DETECTORS_INDEX);
            IndexMetadata indexMetadata =
                    clusterService.state().metadata().index(Detector.DETECTORS_INDEX);

            indexHealth = new ClusterIndexHealth(indexMetadata, indexRoutingTable);
        }
        return indexHealth;
    }

    public ThreadPool getThreadPool() {
        return threadPool;
    }
}
