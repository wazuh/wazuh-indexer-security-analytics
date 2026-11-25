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
package org.opensearch.securityanalytics.indexmanagment;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.rules.engine.LogtestQueryIndex;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Deletes the indices Security Analytics keeps for a log type once the log type is removed.
 *
 * <p>These indices are named after the log type, not after a detector or a space:
 *
 * <ul>
 *   <li>{@code .opensearch-sap-<name>-alerts}, the active alerts;
 *   <li>{@code .opensearch-sap-<name>-alerts-history-<date>-<n>} and {@code
 *       .opensearch-sap-<name>-findings-<date>-<n>}, the alert and finding history;
 *   <li>{@code .opensearch-sap-<name>-detectors-queries-optimized-<uuid>-<n>} and its {@code
 *       _chained_findings} counterpart, every generation of a detector's dedicated query index;
 *   <li>{@code .opensearch-sap-<name>-detectors-queries[-<n>]}, the query index of detectors
 *       created without dedicated query indices;
 *   <li>{@code .opensearch-sap-<name>-detectors-queries-logtest}, the logtest percolator index.
 * </ul>
 *
 * <p>Detector deletion removes only the query index generation behind the detector's alias, and log
 * type deletion only removes the log type document, so without this the rest stays for good.
 *
 * <p>Detectors of any space share these indices by name, so they are kept while any detector of
 * that name remains. The logtest index is shared with log types of the same name in other spaces
 * too, but it is only a cache that logtest rebuilds on its next request.
 */
public class LogTypeIndexCleanup {

    private static final Logger log = LogManager.getLogger(LogTypeIndexCleanup.class);

    /**
     * Log type names whose indices would include an index Security Analytics keeps for itself: {@code
     * correlation} would select {@code .opensearch-sap-correlation-alerts}.
     */
    private static final Set<String> RESERVED_NAMES = Set.of("correlation");

    /** What follows {@code .opensearch-sap-<name>-} in the name of an index of a log type. */
    private static final String SUFFIXES =
            "(alerts"
                    + "|alerts-history-\\d{4}\\.\\d{2}\\.\\d{2}-\\d+"
                    + "|findings-\\d{4}\\.\\d{2}\\.\\d{2}-\\d+"
                    + "|detectors-queries(-\\d{6})?"
                    + "|detectors-queries-optimized-"
                    + "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                    + "(_chained_findings)?-\\d{6})";

    private final Client client;
    private final ClusterService clusterService;

    /**
     * @param client the OpenSearch client.
     * @param clusterService used to list the indices.
     */
    public LogTypeIndexCleanup(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    /**
     * Deletes the indices of a log type that was just removed, unless a detector still uses them.
     *
     * <p>Never fails: a failure is logged and the listener still gets a response, because the log
     * type is already gone and the caller cannot do anything about it.
     *
     * @param logTypeName name of the removed log type.
     * @param listener notified once the indices are deleted, or the cleanup is skipped or failed.
     */
    public void deleteIndicesOfRemovedLogType(String logTypeName, ActionListener<Void> listener) {
        if (RESERVED_NAMES.contains(logTypeName.toLowerCase(Locale.ROOT))) {
            log.warn(
                    "Indices of removed log type [{}] were not deleted: the name matches an internal index",
                    logTypeName);
            listener.onResponse(null);
            return;
        }
        if (!this.clusterService.state().metadata().hasIndex(Detector.DETECTORS_INDEX)) {
            this.deleteIndices(logTypeName, listener);
            return;
        }
        SearchRequest detectors =
                new SearchRequest(Detector.DETECTORS_INDEX)
                        .source(
                                new SearchSourceBuilder()
                                        .size(0)
                                        .query(
                                                QueryBuilders.nestedQuery(
                                                        "detector",
                                                        QueryBuilders.termQuery("detector.detector_type", logTypeName)
                                                                .caseInsensitive(true),
                                                        ScoreMode.None)));
        this.client.search(
                detectors,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (response.getHits().getTotalHits().value() > 0) {
                            log.info(
                                    "Indices of removed log type [{}] were kept: a detector still uses them",
                                    logTypeName);
                            listener.onResponse(null);
                            return;
                        }
                        LogTypeIndexCleanup.this.deleteIndices(logTypeName, listener);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.warn(
                                "Indices of removed log type [{}] were not deleted: the detectors could not be read",
                                logTypeName,
                                e);
                        listener.onResponse(null);
                    }
                });
    }

    private void deleteIndices(String logTypeName, ActionListener<Void> listener) {
        List<String> indices =
                indicesOfLogType(logTypeName, this.clusterService.state().metadata().indices().keySet());
        if (indices.isEmpty()) {
            listener.onResponse(null);
            return;
        }
        DeleteIndexRequest request =
                new DeleteIndexRequest(indices.toArray(new String[0]))
                        .indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN_CLOSED_HIDDEN);
        this.client
                .admin()
                .indices()
                .delete(
                        request,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(AcknowledgedResponse response) {
                                if (response.isAcknowledged()) {
                                    log.info(
                                            "Deleted the indices of removed log type [{}]: {}", logTypeName, indices);
                                } else {
                                    log.warn(
                                            "Deletion of the indices of removed log type [{}] was not acknowledged: {}",
                                            logTypeName,
                                            indices);
                                }
                                listener.onResponse(null);
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.warn(
                                        "Could not delete the indices of removed log type [{}]: {}",
                                        logTypeName,
                                        indices,
                                        e);
                                listener.onResponse(null);
                            }
                        });
    }

    /**
     * Picks the indices of a log type among the given index names.
     *
     * <p>The names are matched whole, so the indices of a log type whose name starts with this one
     * are not picked: {@code wazuh-generic} does not take {@code
     * .opensearch-sap-wazuh-generic-1-alerts}.
     *
     * @param logTypeName name of the log type.
     * @param indexNames names of every index in the cluster.
     * @return the names of the log type's indices.
     */
    static List<String> indicesOfLogType(String logTypeName, Collection<String> indexNames) {
        // Index names carry the log type in lower case (Detector#getDetectorType).
        Pattern pattern =
                Pattern.compile(
                        "^\\.opensearch-sap-"
                                + Pattern.quote(logTypeName.toLowerCase(Locale.ROOT))
                                + "-"
                                + SUFFIXES
                                + "$");
        String logtestIndex = LogtestQueryIndex.indexName(logTypeName);
        List<String> indices = new ArrayList<>();
        for (String name : indexNames) {
            if (name.equals(logtestIndex) || pattern.matcher(name).matches()) {
                indices.add(name);
            }
        }
        return indices;
    }
}
