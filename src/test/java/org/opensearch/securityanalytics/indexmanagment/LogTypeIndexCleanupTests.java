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

import org.apache.lucene.search.TotalHits;
import org.opensearch.Version;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for the deletion of a removed log type's indices. */
public class LogTypeIndexCleanupTests extends OpenSearchTestCase {

    private static final String QUERY_INDEX =
            ".opensearch-sap-windows-rules-detectors-queries-optimized-03c2bbe0-108a-4919-9231-f3fffc28938c";

    /** The indices of the issue's reproduction, plus the generations that accumulate over time. */
    private static final List<String> WINDOWS_RULES_INDICES =
            List.of(
                    ".opensearch-sap-windows-rules-alerts",
                    ".opensearch-sap-windows-rules-alerts-history-2026.11.20-1",
                    ".opensearch-sap-windows-rules-alerts-history-2026.11.21-000002",
                    ".opensearch-sap-windows-rules-findings-2026.11.20-1",
                    ".opensearch-sap-windows-rules-detectors-queries-logtest",
                    QUERY_INDEX + "-000001",
                    QUERY_INDEX + "-000002",
                    QUERY_INDEX + "_chained_findings-000001",
                    ".opensearch-sap-windows-rules-detectors-queries",
                    ".opensearch-sap-windows-rules-detectors-queries-000001");

    /** Every index the log type owns is picked, and nothing else. */
    public void testPicksEveryIndexOfTheLogType() {
        List<String> all = new ArrayList<>(WINDOWS_RULES_INDICES);
        all.add(".opensearch-sap-log-types-config");
        all.add(".opensearch-sap-detectors-config");
        all.add(".opensearch-sap-windows-rules-something-else");
        all.add("wazuh-findings-v5-security");

        assertEquals(
                Set.copyOf(WINDOWS_RULES_INDICES),
                Set.copyOf(LogTypeIndexCleanup.indicesOfLogType("windows-rules", all)));
    }

    /** A log type whose name extends this one keeps its indices. */
    public void testDoesNotPickTheIndicesOfALongerName() {
        List<String> generic1 =
                List.of(
                        ".opensearch-sap-wazuh-generic-1-alerts",
                        ".opensearch-sap-wazuh-generic-1-alerts-history-2026.11.20-1",
                        ".opensearch-sap-wazuh-generic-1-findings-2026.11.20-1",
                        ".opensearch-sap-wazuh-generic-1-detectors-queries-logtest",
                        ".opensearch-sap-wazuh-generic-1-detectors-queries-optimized-"
                                + "03c2bbe0-108a-4919-9231-f3fffc28938c-000001");

        assertEquals(List.of(), LogTypeIndexCleanup.indicesOfLogType("wazuh-generic", generic1));
    }

    /** Index names carry the log type in lower case. */
    public void testMatchesTheLowerCaseName() {
        assertEquals(
                List.of(".opensearch-sap-windows-rules-alerts"),
                LogTypeIndexCleanup.indicesOfLogType(
                        "Windows-Rules", List.of(".opensearch-sap-windows-rules-alerts")));
    }

    /** The logtest index name replaces characters an index name cannot hold. */
    public void testPicksTheSanitizedLogtestIndex() {
        assertEquals(
                List.of(".opensearch-sap-foo_bar-detectors-queries-logtest"),
                LogTypeIndexCleanup.indicesOfLogType(
                        "Foo Bar", List.of(".opensearch-sap-foo_bar-detectors-queries-logtest")));
    }

    /** A regular expression character in the name is matched literally. */
    public void testMatchesTheNameLiterally() {
        assertEquals(
                List.of(),
                LogTypeIndexCleanup.indicesOfLogType("a.b", List.of(".opensearch-sap-axb-alerts")));
    }

    /** With no detector of that type left, the log type's indices are deleted. */
    public void testDeletesTheIndicesWhenNoDetectorRemains() {
        Fixture fixture = new Fixture(true, 0);

        fixture.cleanup("windows-rules");

        assertTrue(fixture.responded.get());
        assertEquals(Set.copyOf(WINDOWS_RULES_INDICES), Set.of(fixture.deleted().indices()));
    }

    /**
     * Detectors of any space share the indices by name, so one left means they are still in use: for
     * example a user detector reading a standard log type.
     */
    public void testKeepsTheIndicesWhileADetectorRemains() {
        Fixture fixture = new Fixture(true, 1);

        fixture.cleanup("windows-rules");

        assertTrue(fixture.responded.get());
        verify(fixture.indicesClient, never()).delete(any(), any());
    }

    /** Without the detectors index there is no detector, and nothing to search. */
    public void testDeletesTheIndicesWhenThereIsNoDetectorsIndex() {
        Fixture fixture = new Fixture(false, 0);

        fixture.cleanup("windows-rules");

        assertTrue(fixture.responded.get());
        verify(fixture.client, never()).search(any(), any());
        assertEquals(Set.copyOf(WINDOWS_RULES_INDICES), Set.of(fixture.deleted().indices()));
    }

    /** When the detectors cannot be read, nothing is deleted, and the caller still gets an answer. */
    public void testKeepsTheIndicesWhenTheDetectorsCannotBeRead() {
        Fixture fixture = new Fixture(true, 0);
        doAnswer(
                        invocation -> {
                            ActionListener<SearchResponse> listener = invocation.getArgument(1);
                            listener.onFailure(new IllegalStateException("all shards failed"));
                            return null;
                        })
                .when(fixture.client)
                .search(any(), any());

        fixture.cleanup("windows-rules");

        assertTrue(fixture.responded.get());
        verify(fixture.indicesClient, never()).delete(any(), any());
    }

    /** A failed deletion is logged, and the caller still gets an answer. */
    public void testAnswersWhenTheDeletionFails() {
        Fixture fixture = new Fixture(true, 0);
        doAnswer(
                        invocation -> {
                            ActionListener<AcknowledgedResponse> listener = invocation.getArgument(1);
                            listener.onFailure(new IllegalStateException("snapshot in progress"));
                            return null;
                        })
                .when(fixture.indicesClient)
                .delete(any(), any());

        fixture.cleanup("windows-rules");

        assertTrue(fixture.responded.get());
    }

    /** {@code correlation} would pick {@code .opensearch-sap-correlation-alerts}. */
    public void testSkipsAReservedName() {
        Fixture fixture = new Fixture(true, 0, ".opensearch-sap-correlation-alerts");

        fixture.cleanup("correlation");

        assertTrue(fixture.responded.get());
        verify(fixture.client, never()).search(any(), any());
        verify(fixture.indicesClient, never()).delete(any(), any());
    }

    /** A client whose cluster holds the windows-rules indices and the given number of detectors. */
    private static class Fixture {
        final Client client = mock(Client.class);
        final IndicesAdminClient indicesClient = mock(IndicesAdminClient.class);
        final AtomicBoolean responded = new AtomicBoolean();
        private final LogTypeIndexCleanup cleanup;

        Fixture(boolean detectorsIndexExists, long detectors, String... extraIndices) {
            Metadata.Builder metadata = Metadata.builder();
            List<String> names = new ArrayList<>(WINDOWS_RULES_INDICES);
            names.addAll(List.of(extraIndices));
            if (detectorsIndexExists) {
                names.add(Detector.DETECTORS_INDEX);
            }
            for (String name : names) {
                metadata.put(
                        IndexMetadata.builder(name)
                                .settings(settings(Version.CURRENT))
                                .numberOfShards(1)
                                .numberOfReplicas(0)
                                .build(),
                        false);
            }
            ClusterService clusterService = mock(ClusterService.class);
            when(clusterService.state())
                    .thenReturn(ClusterState.builder(new ClusterName("test")).metadata(metadata).build());

            SearchResponse response = mock(SearchResponse.class);
            when(response.getHits())
                    .thenReturn(
                            new SearchHits(
                                    new SearchHit[0], new TotalHits(detectors, TotalHits.Relation.EQUAL_TO), 0f));
            doAnswer(
                            invocation -> {
                                SearchRequest request = invocation.getArgument(0);
                                assertArrayEquals(new String[] {Detector.DETECTORS_INDEX}, request.indices());
                                ActionListener<SearchResponse> listener = invocation.getArgument(1);
                                listener.onResponse(response);
                                return null;
                            })
                    .when(this.client)
                    .search(any(), any());

            AdminClient admin = mock(AdminClient.class);
            when(this.client.admin()).thenReturn(admin);
            when(admin.indices()).thenReturn(this.indicesClient);
            doAnswer(
                            invocation -> {
                                ActionListener<AcknowledgedResponse> listener = invocation.getArgument(1);
                                listener.onResponse(new AcknowledgedResponse(true));
                                return null;
                            })
                    .when(this.indicesClient)
                    .delete(any(), any());

            this.cleanup = new LogTypeIndexCleanup(this.client, clusterService);
        }

        void cleanup(String logType) {
            this.cleanup.deleteIndicesOfRemovedLogType(
                    logType,
                    ActionListener.wrap(
                            ignored -> this.responded.set(true), e -> fail("the cleanup must never fail: " + e)));
        }

        DeleteIndexRequest deleted() {
            ArgumentCaptor<DeleteIndexRequest> request =
                    ArgumentCaptor.forClass(DeleteIndexRequest.class);
            verify(this.indicesClient).delete(request.capture(), any());
            return request.getValue();
        }
    }
}
