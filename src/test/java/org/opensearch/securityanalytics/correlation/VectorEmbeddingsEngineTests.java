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
package org.opensearch.securityanalytics.correlation;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.transport.TransportCorrelateFindingAction;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A finding with nothing to correlate is stored on its own in the correlation history index. When
 * the last stored finding is older than the correlation window, the engine first resets the root
 * record of the metadata index and then writes the finding. These tests cover that path: the
 * finding is done once the history write is, and not before.
 */
public class VectorEmbeddingsEngineTests extends OpenSearchTestCase {

    private static final String DETECTOR_TYPE = "network";

    private static final long CORRELATION_WINDOW = TimeValue.timeValueMinutes(5).millis();

    private TransportCorrelateFindingAction.AsyncCorrelateFindingAction action;

    private VectorEmbeddingsEngine engine;

    private Finding finding;

    /** Listeners of the writes to the correlation history index, left for the test to answer. */
    private List<ActionListener<IndexResponse>> historyWrites;

    @Override
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        super.setUp();
        Client client = mock(Client.class);
        this.action = mock(TransportCorrelateFindingAction.AsyncCorrelateFindingAction.class);
        this.engine =
                new VectorEmbeddingsEngine(
                        client, TimeValue.timeValueSeconds(60), CORRELATION_WINDOW, this.action);
        this.finding =
                new Finding(
                        "finding-1",
                        List.of("doc-1"),
                        List.of("doc-1"),
                        "monitor-1",
                        "monitor-name",
                        "wazuh-events-v5-network",
                        List.of(),
                        Instant.now(),
                        null);
        this.historyWrites = new ArrayList<>();

        // The root record is older than the correlation window.
        long rootTimestamp = this.finding.getTimestamp().toEpochMilli() - CORRELATION_WINDOW - 1000L;
        SearchHit root = new SearchHit(0, "root-1", Map.of(), Map.of());
        root.sourceRef(
                new BytesArray(
                        String.format(
                                Locale.ROOT, "{\"root\":true,\"counter\":50,\"timestamp\":%d}", rootTimestamp)));
        SearchResponse metadata = mock(SearchResponse.class);
        when(metadata.isTimedOut()).thenReturn(false);
        when(metadata.getHits())
                .thenReturn(
                        new SearchHits(
                                new SearchHit[] {root}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f));
        doAnswer(
                        inv -> {
                            ((ActionListener<SearchResponse>) inv.getArgument(1)).onResponse(metadata);
                            return null;
                        })
                .when(client)
                .search(any(), any());

        // The reset of the root record succeeds; the history write waits for the test.
        doAnswer(
                        inv -> {
                            IndexRequest request = inv.getArgument(0);
                            ActionListener<IndexResponse> listener = inv.getArgument(1);
                            if (CorrelationIndices.CORRELATION_METADATA_INDEX.equals(request.index())) {
                                listener.onResponse(indexResponse(RestStatus.OK));
                            } else {
                                this.historyWrites.add(listener);
                            }
                            return null;
                        })
                .when(client)
                .index(any(), any());
    }

    private static IndexResponse indexResponse(RestStatus status) {
        IndexResponse response = mock(IndexResponse.class);
        when(response.status()).thenReturn(status);
        return response;
    }

    private static Map<String, CustomLogType> logTypes() {
        return Map.of(
                DETECTOR_TYPE,
                new CustomLogType(
                        null,
                        null,
                        DETECTOR_TYPE,
                        "Network events",
                        "Network Activity",
                        "standard",
                        Map.of("correlation_id", 1)));
    }

    public void testInsertOrphanFindings_staleRoot_completesOnlyAfterTheHistoryWrite() {
        this.engine.insertOrphanFindings(DETECTOR_TYPE, this.finding, 1.0f, logTypes());

        assertEquals("the finding is written to the history index", 1, this.historyWrites.size());
        verify(this.action, never()).onOperation();

        this.historyWrites.get(0).onResponse(indexResponse(RestStatus.CREATED));

        verify(this.action).onOperation();
        verify(this.action, never()).onFailures(any());
    }

    public void testInsertOrphanFindings_staleRoot_failedHistoryWriteFailsTheFinding() {
        this.engine.insertOrphanFindings(DETECTOR_TYPE, this.finding, 1.0f, logTypes());

        assertEquals("the finding is written to the history index", 1, this.historyWrites.size());
        Exception failure = new IllegalStateException("history index is not writable");
        this.historyWrites.get(0).onFailure(failure);

        verify(this.action).onFailures(failure);
        verify(this.action, never()).onOperation();
    }
}
