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

import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.concurrency.OpenSearchRejectedExecutionException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.node.NodeClosedException;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class WazuhEnrichedFindingServiceTests extends OpenSearchTestCase {

    private WazuhEnrichedFindingService service;

    /** Bulks the service sent, in order, with the listener waiting for each one's outcome. */
    private final List<SentBulk> sentBulks = new ArrayList<>();

    private record SentBulk(BulkRequest request, ActionListener<BulkResponse> listener) {}

    /**
     * When set, every bulk fails with it before {@code client.bulk} returns, the way a cluster block
     * rejects a request on the sending node.
     */
    private Exception inlineFailure;

    @Override
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        super.setUp();
        Client client = mock(Client.class);
        doAnswer(
                        invocation -> {
                            SentBulk sent =
                                    new SentBulk(
                                            invocation.getArgument(0),
                                            (ActionListener<BulkResponse>) invocation.getArgument(1));
                            sentBulks.add(sent);
                            if (inlineFailure != null) {
                                sent.listener().onFailure(inlineFailure);
                            }
                            return null;
                        })
                .when(client)
                .bulk(any(BulkRequest.class), any(ActionListener.class));
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
        Scheduler.Cancellable cancellable = mock(Scheduler.Cancellable.class);
        when(threadPool.scheduleWithFixedDelay(any(), any(), any())).thenReturn(cancellable);

        Set<Setting<?>> settingsSet = new HashSet<>();
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_BULK_SIZE);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_MAX_IN_FLIGHT);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_FLUSH_INTERVAL);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_ENRICH_BATCH_SIZE);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_MAX_RETRIES);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_MAX_PENDING_RETRIES);
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

        Map<String, Object> doc = invokeBuildAndIndex(finding, "detection", eventSource, "doc-1", null);

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

        Map<String, Object> doc = invokeBuildAndIndex(finding, "detection", eventSource, "doc-2", null);

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

        Map<String, Object> doc = invokeBuildAndIndex(finding, "detection", eventSource, "doc-3", null);

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

        Map<String, Object> doc = invokeBuildAndIndex(finding, "detection", eventSource, "doc-4", null);

        Map<String, Object> eventObj = (Map<String, Object>) doc.get("event");
        assertNotNull("event object must exist", eventObj);
        assertEquals("process", eventObj.get("category"));
        assertEquals("event", eventObj.get("kind"));
        assertFalse("event.ingested must not be present", eventObj.containsKey("ingested"));
    }

    /**
     * Verifies that {@code wazuh.rule.sigma_id} carries the rule's own upstream Sigma identifier —
     * the optional {@code sigma_id} field of the rule body, preserved on import — and not the
     * rules-index {@code _id} backing the doc-level query, which is regenerated on every space
     * transition.
     */
    @SuppressWarnings("unchecked")
    public void testBuildAndIndex_sigmaIdFromRuleSigmaId() throws Exception {
        String docLevelQueryId = "24503db6-50e3-4dee-b592-db4d1056c775";
        String documentId = "5db5e8e9-85f4-5cac-b97a-9eb39f16aa33";
        String sigmaId = "1da8ce0b-855d-4004-8860-7d64d42063b1";

        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", "2026-05-20T10:00:00.000Z");
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "detection")));

        Finding finding =
                new Finding(
                        "finding-5",
                        List.of("doc-5"),
                        List.of("doc-5"),
                        "monitor-1",
                        "monitor-name",
                        "test-index",
                        Collections.emptyList(),
                        Instant.parse("2026-05-20T10:00:05.000Z"),
                        "high");

        DocLevelQuery query =
                new DocLevelQuery(
                        docLevelQueryId,
                        "Custom rule",
                        Collections.emptyList(),
                        "event.code: \"9999\"",
                        List.of("high"));

        Map<String, Object> doc =
                invokeBuildAndIndex(
                        finding,
                        "detection",
                        eventSource,
                        "doc-5",
                        query,
                        Map.of(
                                "rule",
                                Map.of(
                                        "document", Map.of("id", documentId), "sigma_id", sigmaId, "level", "high")));

        Map<String, Object> rule =
                (Map<String, Object>) ((Map<String, Object>) doc.get("wazuh")).get("rule");
        assertEquals("rule.id must remain the doc-level query id", docLevelQueryId, rule.get("id"));
        assertEquals(
                "rule.sigma_id must be the rule's upstream sigma_id", sigmaId, rule.get("sigma_id"));
        assertNotEquals(
                "rule.sigma_id must not be the doc-level query id", docLevelQueryId, rule.get("sigma_id"));
    }

    /**
     * {@code sigma_id} is optional: a rule that was not imported from upstream Sigma has none, so the
     * field is omitted rather than filled with the rule's own id.
     */
    @SuppressWarnings("unchecked")
    public void testBuildAndIndex_sigmaIdOmittedWhenRuleDeclaresNone() throws Exception {
        String docLevelQueryId = "24503db6-50e3-4dee-b592-db4d1056c775";
        String documentId = "537cfcf0-ce26-49b7-8ea0-29b4ef213057";

        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", "2026-05-20T10:00:00.000Z");
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "detection")));

        Finding finding =
                new Finding(
                        "finding-6",
                        List.of("doc-6"),
                        List.of("doc-6"),
                        "monitor-1",
                        "monitor-name",
                        "test-index",
                        Collections.emptyList(),
                        Instant.parse("2026-05-20T10:00:05.000Z"),
                        "high");

        DocLevelQuery query =
                new DocLevelQuery(
                        docLevelQueryId,
                        "Custom rule without upstream Sigma id",
                        Collections.emptyList(),
                        "event.code: \"9999\"",
                        List.of("high"));

        Map<String, Object> doc =
                invokeBuildAndIndex(
                        finding,
                        "detection",
                        eventSource,
                        "doc-6",
                        query,
                        Map.of("rule", Map.of("document", Map.of("id", documentId), "level", "high")));

        Map<String, Object> rule =
                (Map<String, Object>) ((Map<String, Object>) doc.get("wazuh")).get("rule");
        assertEquals("rule.id must remain the doc-level query id", docLevelQueryId, rule.get("id"));
        assertFalse(
                "sigma_id must be absent when the rule declares no upstream Sigma id",
                rule.containsKey("sigma_id"));
    }

    /**
     * Without rule metadata the upstream identifier is unknown, so {@code sigma_id} is omitted rather
     * than filled with the unrelated rules-index id.
     */
    @SuppressWarnings("unchecked")
    public void testBuildAndIndex_sigmaIdOmittedWhenMetadataMissing() throws Exception {
        String docLevelQueryId = "ddf46be9-dbda-59a6-8b3e-ef7b798f07b2";

        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", "2026-05-20T10:00:00.000Z");
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "detection")));

        Finding finding =
                new Finding(
                        "finding-7",
                        List.of("doc-7"),
                        List.of("doc-7"),
                        "monitor-1",
                        "monitor-name",
                        "test-index",
                        Collections.emptyList(),
                        Instant.parse("2026-05-20T10:00:05.000Z"),
                        "high");

        DocLevelQuery query =
                new DocLevelQuery(
                        docLevelQueryId,
                        "Pre-packaged rule",
                        Collections.emptyList(),
                        "event.code: \"4625\"",
                        List.of("high"));

        Map<String, Object> doc =
                invokeBuildAndIndex(finding, "detection", eventSource, "doc-7", query, Map.of());

        Map<String, Object> rule =
                (Map<String, Object>) ((Map<String, Object>) doc.get("wazuh")).get("rule");
        assertEquals("rule.id must remain the doc-level query id", docLevelQueryId, rule.get("id"));
        assertFalse(
                "sigma_id must be absent when the rule metadata is unavailable",
                rule.containsKey("sigma_id"));
    }

    // ── Deterministic document id ───────────────────────────────────────────

    /**
     * Reprocessing the same event against the same rule — what a detector does when its checkpoint
     * fails to advance and it replays a window — must target the same document id, so the write is
     * rejected rather than appended as an indistinguishable copy.
     */
    public void testBuildAndIndex_sameMatchKeysToSameId() throws Exception {
        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", "2026-05-20T10:00:00.000Z");
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "detection")));

        DocLevelQuery query =
                new DocLevelQuery(
                        "rule-1",
                        "Rootkit detected",
                        Collections.emptyList(),
                        "event.code: \"1\"",
                        List.of("high"));
        Finding finding = finding("finding-1", "doc-1", ".ds-wazuh-events-v5-security-000001");

        List<IndexRequest> first =
                invokeBuildAndCaptureRequests(finding, "detection", eventSource, "doc-1", List.of(query));
        assertEquals(1, first.size());
        String id = first.get(0).id();
        assertNotNull("The enriched finding must carry an explicit document id", id);

        pendingRequests().clear();

        // Same event, same rule, rebuilt from scratch: a replay.
        List<IndexRequest> replay =
                invokeBuildAndCaptureRequests(
                        finding("finding-2", "doc-1", ".ds-wazuh-events-v5-security-000001"),
                        "detection",
                        eventSource,
                        "doc-1",
                        List.of(query));
        assertEquals(1, replay.size());
        assertEquals("A replayed match must key to the same document id", id, replay.get(0).id());
        assertEquals(
                "The id must be derived from the match, not from the finding",
                WazuhEnrichedFindingService.dedupId(
                        ".ds-wazuh-events-v5-security-000001", "doc-1", "rule-1"),
                id);
    }

    /** One event matching two rules is two distinct findings, so the ids must differ. */
    public void testBuildAndIndex_idVariesPerRule() throws Exception {
        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", "2026-05-20T10:00:00.000Z");
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "detection")));

        DocLevelQuery first =
                new DocLevelQuery(
                        "rule-1", "First rule", Collections.emptyList(), "event.code: \"1\"", List.of("high"));
        DocLevelQuery second =
                new DocLevelQuery(
                        "rule-2", "Second rule", Collections.emptyList(), "event.code: \"1\"", List.of("low"));

        List<IndexRequest> requests =
                invokeBuildAndCaptureRequests(
                        finding("finding-1", "doc-1", "source-index"),
                        "detection",
                        eventSource,
                        "doc-1",
                        List.of(first, second));

        assertEquals(2, requests.size());
        assertNotEquals(
                "Two rules matching one event must produce two documents",
                requests.get(0).id(),
                requests.get(1).id());
    }

    /** A finding carrying no rule fields is still keyed deterministically, on the event alone. */
    public void testBuildAndIndex_idWithoutRules() throws Exception {
        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", "2026-05-20T10:00:00.000Z");
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "detection")));

        List<IndexRequest> requests =
                invokeBuildAndCaptureRequests(
                        finding("finding-1", "doc-1", "source-index"),
                        "detection",
                        eventSource,
                        "doc-1",
                        List.of());

        assertEquals(1, requests.size());
        assertEquals(
                WazuhEnrichedFindingService.dedupId("source-index", "doc-1", null), requests.get(0).id());
    }

    /**
     * The key is stable, changes with every component, and cannot be forged by shifting characters
     * between components — the property the length prefixes buy.
     */
    public void testDedupId_stableAndCollisionResistant() {
        assertEquals(
                WazuhEnrichedFindingService.dedupId("index", "doc", "rule"),
                WazuhEnrichedFindingService.dedupId("index", "doc", "rule"));

        assertNotEquals(
                WazuhEnrichedFindingService.dedupId("index", "doc", "rule"),
                WazuhEnrichedFindingService.dedupId("other", "doc", "rule"));
        assertNotEquals(
                WazuhEnrichedFindingService.dedupId("index", "doc", "rule"),
                WazuhEnrichedFindingService.dedupId("index", "other", "rule"));
        assertNotEquals(
                WazuhEnrichedFindingService.dedupId("index", "doc", "rule"),
                WazuhEnrichedFindingService.dedupId("index", "doc", "other"));

        assertNotEquals(
                "Shifting a character between components must not collide",
                WazuhEnrichedFindingService.dedupId("ab", "c", "d"),
                WazuhEnrichedFindingService.dedupId("a", "bc", "d"));

        assertNotEquals(
                "A missing rule id must not collide with an empty one",
                WazuhEnrichedFindingService.dedupId("index", "doc", null),
                WazuhEnrichedFindingService.dedupId("index", "docrule", null));
    }

    // ── Bulk response handling ──────────────────────────────────────────────

    /**
     * A 409 on a {@code create} is the deterministic id rejecting a replay, which is the intended
     * behaviour: it must be counted as a deduplication, and must not hide the failures that do need
     * attention.
     */
    public void testHandleBulkResponse_conflictsCountedAsDeduplicated() throws Exception {
        assertEquals(0L, service.getDedupedCount());

        sendQueued("dup-1", "dup-2", "bad-1");
        respond(
                0,
                failedItem(0, "dup-1", RestStatus.CONFLICT),
                failedItem(1, "dup-2", RestStatus.CONFLICT),
                failedItem(2, "bad-1", RestStatus.BAD_REQUEST));

        assertEquals("Only the conflicts count as deduplicated replays", 2L, service.getDedupedCount());
        assertEquals("The mapping error is dropped, not deduplicated", 1L, service.getDroppedCount());
    }

    /** A batch with nothing to report leaves the counters untouched. */
    public void testHandleBulkResponse_noFailuresLeavesCounterUntouched() throws Exception {
        sendQueued("ok-1");
        respond(0);
        assertEquals(0L, service.getDedupedCount());
        assertEquals(0L, service.getRetriedCount());
        assertEquals(0L, service.getDroppedCount());
    }

    /**
     * A write rejected under load is resent on the next periodic flush, and only that write: the
     * items that succeeded are not sent twice.
     */
    public void testTransientItemFailure_resentOnPeriodicFlush() throws Exception {
        sendQueued("ok-1", "busy-1");
        respond(0, failedItem(1, "busy-1", RestStatus.TOO_MANY_REQUESTS));

        assertEquals(1L, service.getRetriedCount());
        assertEquals(0L, service.getDroppedCount());

        invokePrivate("periodicFlush");
        assertEquals("The retry goes out as a bulk of its own", 2, sentBulks.size());
        assertEquals(List.of("busy-1"), ids(sentBulks.get(1)));

        respond(1);
        assertEquals(0L, service.getDroppedCount());
    }

    /**
     * A resend of a write that had in fact landed the first time comes back as a 409, which the
     * deterministic id turns into a discarded duplicate instead of a second copy.
     */
    public void testRetryOfWriteThatLanded_countedAsDeduplicated() throws Exception {
        sendQueued("slow-1");
        respond(0, failedItem(0, "slow-1", RestStatus.SERVICE_UNAVAILABLE));

        invokePrivate("periodicFlush");
        respond(1, failedItem(0, "slow-1", RestStatus.CONFLICT));

        assertEquals(1L, service.getDedupedCount());
        assertEquals(0L, service.getDroppedCount());
    }

    /**
     * A write block is a 403 that stays until someone lifts it: resending would only fail again, so
     * the write is dropped on the first attempt.
     */
    public void testPermanentItemFailure_droppedWithoutRetry() throws Exception {
        sendQueued("blocked-1");
        respond(0, failedItem(0, "blocked-1", RestStatus.FORBIDDEN));

        assertEquals(0L, service.getRetriedCount());
        assertEquals(1L, service.getDroppedCount());

        invokePrivate("periodicFlush");
        assertEquals("Nothing is left to resend", 1, sentBulks.size());
    }

    /** A bulk the node rejected as a whole is resent in full. */
    public void testTransientBulkFailure_requeuesEveryWrite() throws Exception {
        sendQueued("a-1", "a-2", "a-3");
        sentBulks.get(0).listener().onFailure(new OpenSearchRejectedExecutionException("rejected"));

        assertEquals(3L, service.getRetriedCount());
        assertEquals(0L, service.getDroppedCount());

        invokePrivate("periodicFlush");
        assertEquals(List.of("a-1", "a-2", "a-3"), ids(sentBulks.get(1)));
    }

    /** A bulk that failed as a whole for a permanent reason drops every write in it. */
    public void testPermanentBulkFailure_dropsEveryWrite() throws Exception {
        sendQueued("a-1", "a-2");
        sentBulks.get(0).listener().onFailure(new IllegalArgumentException("malformed"));

        assertEquals(0L, service.getRetriedCount());
        assertEquals(2L, service.getDroppedCount());
    }

    /** A write that keeps failing is given up on after the configured number of resends. */
    public void testRetriesExhausted_writeDropped() throws Exception {
        service.setMaxRetries(2);
        sendQueued("busy-1");
        respond(0, failedItem(0, "busy-1", RestStatus.TOO_MANY_REQUESTS));

        for (int resend = 1; resend <= 2; resend++) {
            invokePrivate("periodicFlush");
            respond(resend, failedItem(0, "busy-1", RestStatus.TOO_MANY_REQUESTS));
        }

        assertEquals("The first attempt plus two resends", 3, sentBulks.size());
        assertEquals(2L, service.getRetriedCount());
        assertEquals(1L, service.getDroppedCount());

        invokePrivate("periodicFlush");
        assertEquals("The dropped write is not sent again", 3, sentBulks.size());
    }

    /** With retries disabled, a transient failure is dropped straight away. */
    public void testRetriesDisabled_transientFailureDropped() throws Exception {
        service.setMaxRetries(0);
        sendQueued("busy-1");
        respond(0, failedItem(0, "busy-1", RestStatus.TOO_MANY_REQUESTS));

        assertEquals(0L, service.getRetriedCount());
        assertEquals(1L, service.getDroppedCount());
    }

    /**
     * The retry queue is bounded: during a long outage, writes past the limit are dropped and counted
     * instead of growing the heap.
     */
    public void testRetryQueueFull_overflowDropped() throws Exception {
        service.setMaxPendingRetries(2);
        sendQueued("a-1", "a-2", "a-3");
        sentBulks.get(0).listener().onFailure(new OpenSearchRejectedExecutionException("rejected"));

        assertEquals(2L, service.getRetriedCount());
        assertEquals(1L, service.getDroppedCount());

        invokePrivate("periodicFlush");
        assertEquals(List.of("a-1", "a-2"), ids(sentBulks.get(1)));
    }

    /** A large retry backlog is resent in bulks no larger than the configured bulk size. */
    public void testRetryBacklog_resentInBulkSizedChunks() throws Exception {
        service.setBulkBatchSize(10);
        String[] backlog = new String[25];
        for (int i = 0; i < backlog.length; i++) {
            backlog[i] = "a-" + i;
        }
        sendQueued(backlog);
        sentBulks.get(0).listener().onFailure(new OpenSearchRejectedExecutionException("rejected"));

        invokePrivate("periodicFlush");
        assertEquals(4, sentBulks.size());
        assertEquals(10, sentBulks.get(1).request().numberOfActions());
        assertEquals(10, sentBulks.get(2).request().numberOfActions());
        assertEquals(5, sentBulks.get(3).request().numberOfActions());
    }

    /**
     * The size-triggered flush sends only new writes: resends wait for the periodic flush, so a node
     * shedding load is not hit again as soon as the next batch fills.
     */
    public void testSizeTriggeredFlush_leavesRetriesForPeriodicFlush() throws Exception {
        sendQueued("busy-1");
        respond(0, failedItem(0, "busy-1", RestStatus.TOO_MANY_REQUESTS));

        sendQueued("new-1");
        assertEquals(List.of("new-1"), ids(sentBulks.get(1)));
    }

    /**
     * A bulk rejected before {@code client.bulk} returns puts its writes back on the retry queue
     * mid-flush. They must still wait for the next periodic flush instead of being resent in the same
     * one.
     */
    public void testInlineFailure_resendWaitsForNextPeriodicFlush() throws Exception {
        inlineFailure =
                new ClusterBlockException(Set.of(IndexMetadata.INDEX_READ_ONLY_ALLOW_DELETE_BLOCK));
        pendingRequests()
                .add(
                        new IndexRequest("wazuh-findings-v5-detection")
                                .id("busy-1")
                                .source(Map.of("id", "busy-1")));

        invokePrivate("periodicFlush");
        assertEquals("Only the first attempt goes out in this flush", 1, sentBulks.size());
        assertEquals(1L, service.getRetriedCount());

        invokePrivate("periodicFlush");
        assertEquals("One resend per flush", 2, sentBulks.size());
        assertEquals(List.of("busy-1"), ids(sentBulks.get(1)));
    }

    /** Statuses and causes that clear up on their own are retried; the rest are not. */
    public void testIsRetryable() {
        assertTrue(WazuhEnrichedFindingService.isRetryable(RestStatus.TOO_MANY_REQUESTS, null));
        assertTrue(WazuhEnrichedFindingService.isRetryable(RestStatus.SERVICE_UNAVAILABLE, null));
        assertTrue(WazuhEnrichedFindingService.isRetryable(RestStatus.GATEWAY_TIMEOUT, null));
        assertTrue(
                "A node shutting down reports a 500 but is transient",
                WazuhEnrichedFindingService.isRetryable(
                        RestStatus.INTERNAL_SERVER_ERROR, new NodeClosedException((DiscoveryNode) null)));

        assertFalse(WazuhEnrichedFindingService.isRetryable(RestStatus.BAD_REQUEST, null));
        assertFalse(WazuhEnrichedFindingService.isRetryable(RestStatus.NOT_FOUND, null));
        assertFalse(
                WazuhEnrichedFindingService.isRetryable(
                        RestStatus.INTERNAL_SERVER_ERROR, new IllegalStateException("bug")));

        ClusterBlockException writeBlock =
                new ClusterBlockException(Set.of(IndexMetadata.INDEX_WRITE_BLOCK));
        assertFalse(
                "A write block stays until it is lifted",
                WazuhEnrichedFindingService.isRetryable(writeBlock.status(), writeBlock));
        ClusterBlockException floodStage =
                new ClusterBlockException(Set.of(IndexMetadata.INDEX_READ_ONLY_ALLOW_DELETE_BLOCK));
        assertTrue(
                "The flood-stage block is lifted when disk frees up",
                WazuhEnrichedFindingService.isRetryable(floodStage.status(), floodStage));
    }

    // ── Helper ──────────────────────────────────────────────────────────────

    /** A finding over a single source document, with the queries supplied separately. */
    private static Finding finding(String id, String docId, String index) {
        return new Finding(
                id,
                List.of(docId),
                List.of(docId),
                "monitor-1",
                "monitor-name",
                index,
                Collections.emptyList(),
                Instant.now(),
                "high");
    }

    /**
     * Invokes the private buildDocAndIndex method and captures the document that would be indexed. We
     * intercept at the indexEnrichedFinding level by overriding the pending-requests queue. A {@code
     * null} primaryQuery maps to the empty-queries path (base doc indexed without rule fields).
     */
    private Map<String, Object> invokeBuildAndIndex(
            Finding finding,
            String category,
            Map<String, Object> eventSource,
            String docId,
            DocLevelQuery primaryQuery)
            throws Exception {
        return invokeBuildAndIndex(finding, category, eventSource, docId, primaryQuery, Map.of());
    }

    /**
     * Same as above, seeding the rule metadata cache with {@code ruleMetadata} for the primary
     * query's id. An empty map stands for "metadata unavailable", matching what the service caches
     * when the rules-index lookup returns nothing for a query.
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

        if (primaryQuery != null) {
            var cacheField = WazuhEnrichedFindingService.class.getDeclaredField("ruleMetadataCache");
            cacheField.setAccessible(true);
            ((Map<String, Map<String, Object>>) cacheField.get(service))
                    .put(primaryQuery.getId(), ruleMetadata);
        }

        Method method =
                WazuhEnrichedFindingService.class.getDeclaredMethod(
                        "buildDocAndIndex", Finding.class, String.class, Map.class, String.class, List.class);
        method.setAccessible(true);
        method.invoke(service, finding, category, eventSource, docId, queries);

        // The last pending request contains the indexed document
        var lastRequest = pendingRequests().stream().reduce((first, second) -> second).orElse(null);
        assertNotNull("An index request must have been queued", lastRequest);
        return lastRequest.sourceAsMap();
    }

    /**
     * Invokes the private buildDocAndIndex method with an arbitrary query list and returns the index
     * requests it queued, in order. Unlike {@link #invokeBuildAndIndex} this exposes the requests
     * themselves, so a test can assert on the document id and not only on the source. Rule metadata
     * is seeded as unavailable for every query, which the id does not depend on.
     */
    @SuppressWarnings("unchecked")
    private List<IndexRequest> invokeBuildAndCaptureRequests(
            Finding finding,
            String category,
            Map<String, Object> eventSource,
            String docId,
            List<DocLevelQuery> queries)
            throws Exception {

        var cacheField = WazuhEnrichedFindingService.class.getDeclaredField("ruleMetadataCache");
        cacheField.setAccessible(true);
        var cache = (Map<String, Map<String, Object>>) cacheField.get(service);
        for (DocLevelQuery query : queries) {
            cache.put(query.getId(), Map.of());
        }

        Method method =
                WazuhEnrichedFindingService.class.getDeclaredMethod(
                        "buildDocAndIndex", Finding.class, String.class, Map.class, String.class, List.class);
        method.setAccessible(true);
        method.invoke(service, finding, category, eventSource, docId, queries);

        return List.copyOf(pendingRequests());
    }

    @SuppressWarnings("unchecked")
    private ConcurrentLinkedQueue<IndexRequest> pendingRequests() throws Exception {
        var pendingField = WazuhEnrichedFindingService.class.getDeclaredField("pendingRequests");
        pendingField.setAccessible(true);
        return (ConcurrentLinkedQueue<IndexRequest>) pendingField.get(service);
    }

    /** Queues one index request per id and sends them as a single bulk. */
    private void sendQueued(String... ids) throws Exception {
        for (String id : ids) {
            pendingRequests()
                    .add(new IndexRequest("wazuh-findings-v5-detection").id(id).source(Map.of("id", id)));
        }
        invokePrivate("drainAndFlush");
    }

    /** Completes the {@code index}-th sent bulk with the given failed items; none means success. */
    private void respond(int index, BulkItemResponse... failedItems) {
        sentBulks.get(index).listener().onResponse(new BulkResponse(failedItems, 1L));
    }

    private static List<String> ids(SentBulk bulk) {
        return bulk.request().requests().stream().map(DocWriteRequest::id).toList();
    }

    private void invokePrivate(String name) throws Exception {
        Method method = WazuhEnrichedFindingService.class.getDeclaredMethod(name);
        method.setAccessible(true);
        method.invoke(service);
    }

    private static BulkItemResponse failedItem(int itemId, String id, RestStatus status) {
        return new BulkItemResponse(
                itemId,
                DocWriteRequest.OpType.CREATE,
                new BulkItemResponse.Failure(
                        "wazuh-findings-v5-detection", id, new IllegalStateException("failed"), status));
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
