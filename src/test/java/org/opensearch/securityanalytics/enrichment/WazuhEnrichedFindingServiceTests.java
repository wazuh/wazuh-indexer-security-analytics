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
package org.opensearch.securityanalytics.enrichment;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class WazuhEnrichedFindingServiceTests extends OpenSearchTestCase {

    private WazuhEnrichedFindingService service;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        Client client = mock(Client.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
        Scheduler.Cancellable cancellable = mock(Scheduler.Cancellable.class);
        when(threadPool.scheduleWithFixedDelay(any(), any(), any())).thenReturn(cancellable);

        Set<Setting<?>> settingsSet = new HashSet<>();
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_BULK_SIZE);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_MAX_IN_FLIGHT);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_FLUSH_INTERVAL);
        ClusterSettings clusterSettings = new ClusterSettings(Settings.EMPTY, settingsSet);
        ClusterService clusterService = mock(ClusterService.class);
        when(clusterService.getSettings()).thenReturn(Settings.EMPTY);
        when(clusterService.getClusterSettings()).thenReturn(clusterSettings);

        service =
                new WazuhEnrichedFindingService(
                        client, true, TimeValue.timeValueSeconds(30), threadPool, 10000, clusterService);
    }

    @Override
    public void tearDown() throws Exception {
        service.close();
        super.tearDown();
    }

    /**
     * Verifies that the enriched finding's {@code @timestamp} is taken from the original event
     * source, not from the finding's own timestamp.
     */
    @SuppressWarnings("unchecked")
    public void testBuildAndIndex_timestampFromEventSource() throws Exception {
        String eventTimestamp = "2026-05-20T10:00:00.000Z";
        Instant findingTimestamp = Instant.parse("2026-05-20T10:00:05.000Z");

        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", eventTimestamp);
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "detection")));

        Finding finding =
                new Finding(
                        "finding-1",
                        List.of("doc-1"),
                        List.of("doc-1"),
                        "monitor-1",
                        "monitor-name",
                        "test-index",
                        Collections.emptyList(),
                        findingTimestamp,
                        "high");

        Map<String, Object> doc =
                invokeBuildAndIndex(finding, "detection", eventSource, "doc-1", null, Map.of());

        assertEquals(
                "Finding @timestamp must match the original event's @timestamp",
                eventTimestamp,
                doc.get("@timestamp"));
    }

    /** Verifies that the enriched finding does NOT contain {@code event.ingested}. */
    @SuppressWarnings("unchecked")
    public void testBuildAndIndex_noEventIngested() throws Exception {
        String eventTimestamp = "2026-05-20T10:00:00.000Z";

        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", eventTimestamp);
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "detection")));

        Finding finding =
                new Finding(
                        "finding-2",
                        List.of("doc-2"),
                        List.of("doc-2"),
                        "monitor-1",
                        "monitor-name",
                        "test-index",
                        Collections.emptyList(),
                        Instant.now(),
                        "high");

        Map<String, Object> doc =
                invokeBuildAndIndex(finding, "detection", eventSource, "doc-2", null, Map.of());

        Map<String, Object> eventObj = (Map<String, Object>) doc.get("event");
        assertNotNull("event object must exist", eventObj);
        assertFalse(
                "event.ingested must not be present in enriched findings",
                eventObj.containsKey("ingested"));
    }

    /** Verifies that event.doc_id and event.index are still populated correctly. */
    @SuppressWarnings("unchecked")
    public void testBuildAndIndex_eventMetadataFields() throws Exception {
        String eventTimestamp = "2026-05-20T10:00:00.000Z";

        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", eventTimestamp);
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "detection")));

        Finding finding =
                new Finding(
                        "finding-3",
                        List.of("doc-3"),
                        List.of("doc-3"),
                        "monitor-1",
                        "monitor-name",
                        "source-index",
                        Collections.emptyList(),
                        Instant.now(),
                        "high");

        Map<String, Object> doc =
                invokeBuildAndIndex(finding, "detection", eventSource, "doc-3", null, Map.of());

        Map<String, Object> eventObj = (Map<String, Object>) doc.get("event");
        assertNotNull("event object must exist", eventObj);
        assertEquals("doc-3", eventObj.get("doc_id"));
        assertEquals("source-index", eventObj.get("index"));
    }

    /** Verifies that existing event fields from the source are preserved in the enriched finding. */
    @SuppressWarnings("unchecked")
    public void testBuildAndIndex_preservesExistingEventFields() throws Exception {
        String eventTimestamp = "2026-05-20T10:00:00.000Z";

        Map<String, Object> existingEvent = new HashMap<>();
        existingEvent.put("category", "process");
        existingEvent.put("kind", "event");

        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", eventTimestamp);
        eventSource.put("event", existingEvent);
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "detection")));

        Finding finding =
                new Finding(
                        "finding-4",
                        List.of("doc-4"),
                        List.of("doc-4"),
                        "monitor-1",
                        "monitor-name",
                        "test-index",
                        Collections.emptyList(),
                        Instant.now(),
                        "high");

        Map<String, Object> doc =
                invokeBuildAndIndex(finding, "detection", eventSource, "doc-4", null, Map.of());

        Map<String, Object> eventObj = (Map<String, Object>) doc.get("event");
        assertNotNull("event object must exist", eventObj);
        assertEquals("process", eventObj.get("category"));
        assertEquals("event", eventObj.get("kind"));
        assertFalse("event.ingested must not be present", eventObj.containsKey("ingested"));
    }

    // ── Helper ──────────────────────────────────────────────────────────────

    /**
     * Invokes the private buildDocAndIndex method and captures the document that would be indexed. We
     * intercept at the indexEnrichedFinding level by overriding the pending-requests queue. A {@code
     * null} primaryQuery maps to the empty-queries path (base doc indexed without rule fields).
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> invokeBuildAndIndex(
            Finding finding,
            String category,
            Map<String, Object> eventSource,
            String docId,
            DocLevelQuery primaryQuery,
            Map<String, Object> ruleMetadata)
            throws Exception {

        List<DocLevelQuery> queries = primaryQuery == null ? List.of() : List.of(primaryQuery);

        Method method =
                WazuhEnrichedFindingService.class.getDeclaredMethod(
                        "buildDocAndIndex", Finding.class, String.class, Map.class, String.class, List.class);
        method.setAccessible(true);
        method.invoke(service, finding, category, eventSource, docId, queries);

        // The last pending request contains the indexed document
        var pendingField = WazuhEnrichedFindingService.class.getDeclaredField("pendingRequests");
        pendingField.setAccessible(true);
        var queue =
                (java.util.concurrent.ConcurrentLinkedQueue<org.opensearch.action.index.IndexRequest>)
                        pendingField.get(service);
        var lastRequest = queue.stream().reduce((first, second) -> second).orElse(null);
        assertNotNull("An index request must have been queued", lastRequest);
        return lastRequest.sourceAsMap();
    }

    public void testSetBulkBatchSize_updatesField() throws Exception {
        Field field = WazuhEnrichedFindingService.class.getDeclaredField("bulkBatchSize");
        field.setAccessible(true);

        service.setBulkBatchSize(200);
        assertEquals(200, field.get(service));

        service.setBulkBatchSize(10);
        assertEquals(10, field.get(service));
    }

    public void testSetMaxInFlight_updatesField() throws Exception {
        Field field = WazuhEnrichedFindingService.class.getDeclaredField("maxInFlight");
        field.setAccessible(true);

        service.setMaxInFlight(8);
        assertEquals(8, field.get(service));

        service.setMaxInFlight(2);
        assertEquals(2, field.get(service));
    }

    public void testSetFlushInterval_reschedulesTask() {
        service.setFlushInterval(3);
        service.setFlushInterval(60);
    }
}
