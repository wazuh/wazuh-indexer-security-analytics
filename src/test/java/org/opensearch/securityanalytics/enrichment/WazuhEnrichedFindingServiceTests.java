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

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.NoShardAvailableActionException;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.OpenSearchExecutors;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.concurrency.OpenSearchRejectedExecutionException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.get.GetResult;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.node.NodeClosedException;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.test.MockLogAppender;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.RemoteTransportException;
import org.opensearch.transport.client.Client;
import org.hamcrest.MatcherAssert;
import org.junit.Assert;

import java.io.IOException;
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
import java.util.concurrent.CopyOnWriteArrayList;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class WazuhEnrichedFindingServiceTests extends OpenSearchTestCase {

    private WazuhEnrichedFindingService service;

    /** Bulks the service sent, in order, with the listener waiting for each one's outcome. */
    private final List<SentBulk> sentBulks = new ArrayList<>();

    private record SentBulk(BulkRequest request, ActionListener<BulkResponse> listener) {}

    /** Source-event MultiGets the service sent, in order, with the listener waiting for each one. */
    private final List<SentMultiGet> sentMultiGets = new ArrayList<>();

    private record SentMultiGet(MultiGetRequest request, ActionListener<MultiGetResponse> listener) {}

    /**
     * When set, every bulk fails with it before {@code client.bulk} returns, the way a cluster block
     * rejects a request on the sending node.
     */
    private Exception inlineFailure;

    /**
     * When set, every source-event MultiGet throws it before {@code client.multiGet} returns, the way
     * a rejected submission fails on the sending node.
     */
    private RuntimeException inlineReadFailure;

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
        doAnswer(
                        invocation -> {
                            sentMultiGets.add(
                                    new SentMultiGet(
                                            invocation.getArgument(0),
                                            (ActionListener<MultiGetResponse>) invocation.getArgument(1)));
                            if (this.inlineReadFailure != null) {
                                throw this.inlineReadFailure;
                            }
                            return null;
                        })
                .when(client)
                .multiGet(any(MultiGetRequest.class), any(ActionListener.class));
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
        // Enriched documents are built on the calling thread, so a test sees them queued for writing
        // as soon as the source MultiGet is answered.
        when(threadPool.executor(ThreadPool.Names.GENERIC))
                .thenReturn(OpenSearchExecutors.newDirectExecutorService());
        Scheduler.Cancellable cancellable = mock(Scheduler.Cancellable.class);
        when(threadPool.scheduleWithFixedDelay(any(), any(), any())).thenReturn(cancellable);

        Set<Setting<?>> settingsSet = new HashSet<>();
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_BULK_SIZE);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_MAX_IN_FLIGHT);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_FLUSH_INTERVAL);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_ENRICH_BATCH_SIZE);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_MAX_RETRIES);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_MAX_PENDING_RETRIES);
        settingsSet.add(SecurityAnalyticsSettings.ENRICHED_FINDINGS_MAX_PENDING);
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

    // ── Rule title interpolation ────────────────────────────────────────────

    /**
     * A title placeholder that points to an array field renders the elements joined with a space, so
     * a rule titled after {@code process.args} names the command that matched instead of ending in an
     * empty suffix.
     */
    @SuppressWarnings("unchecked")
    public void testBuildAndIndex_titleRendersArrayPlaceholder() throws Exception {
        Map<String, Object> eventSource = new HashMap<>();
        eventSource.put("@timestamp", "2026-05-20T10:00:00.000Z");
        eventSource.put("wazuh", Map.of("integration", Map.of("category", "system-activity")));
        eventSource.put(
                "process", Map.of("args", List.of("/usr/bin/tar", "-czf", "/tmp/out.tgz", "/srv")));

        DocLevelQuery query =
                new DocLevelQuery(
                        "rule-1",
                        "Archive created via tar - {{ process.args }}",
                        Collections.emptyList(),
                        "process.name: \"tar\"",
                        List.of("low"));
        Finding finding = finding("finding-1", "doc-1", ".ds-wazuh-events-v5-system-activity-000001");

        Map<String, Object> doc =
                invokeBuildAndIndex(finding, "system-activity", eventSource, "doc-1", query);

        Map<String, Object> rule =
                (Map<String, Object>) ((Map<String, Object>) doc.get("wazuh")).get("rule");
        assertEquals(
                "Archive created via tar - /usr/bin/tar -czf /tmp/out.tgz /srv", rule.get("title"));
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

    // ── Triggering event reads ─────────────────────────────────────────────

    /**
     * The triggering events are read from the primary: a replica that has not applied an event yet
     * answers that it does not exist, although the detector has already matched it.
     */
    public void testRead_prefersThePrimary() {
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", "doc-1", EVENTS));

        Assert.assertEquals("_primary_first", this.sentMultiGets.get(0).request().preference());
    }

    /**
     * An event whose read was rejected under load is read again on the next periodic flush, and only
     * that event: the finding's other event, read the first time, is written straight away and not
     * fetched twice. The finding ends up complete.
     */
    public void testRead_rejectedEventReadAgainOnNextFlush() throws Exception {
        this.service.enrich(
                WazuhEnrichedFindingServiceTests.finding("f-1", List.of("doc-1", "doc-2"), EVENTS));
        this.answer(
                0,
                WazuhEnrichedFindingServiceTests.found("doc-1"),
                WazuhEnrichedFindingServiceTests.failed(
                        "doc-2", WazuhEnrichedFindingServiceTests.rejected()));

        Assert.assertEquals(List.of("doc-1"), this.writtenEventIds());
        Assert.assertEquals(1L, this.service.getRetriedReadCount());
        Assert.assertEquals("The read waits for the flush", 1, this.sentMultiGets.size());

        this.invokePrivate("periodicFlush");
        Assert.assertEquals(2, this.sentMultiGets.size());
        Assert.assertEquals(
                List.of("doc-2"), WazuhEnrichedFindingServiceTests.docIds(this.sentMultiGets.get(1)));
        Assert.assertEquals("_primary_first", this.sentMultiGets.get(1).request().preference());

        this.answer(1, WazuhEnrichedFindingServiceTests.found("doc-2"));
        Assert.assertEquals(List.of("doc-1", "doc-2"), this.writtenEventIds());
        Assert.assertEquals(0L, this.service.getUnreadCount());
        Assert.assertEquals(0L, this.service.getMissingCount());
    }

    /**
     * An event not found on the first read is read again, since the detector matched it: a copy that
     * had not applied it yet answers the same way. Found on the second read, its finding is written.
     */
    public void testRead_eventNotFoundThenFound_written() throws Exception {
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", "doc-1", EVENTS));
        this.answer(0, WazuhEnrichedFindingServiceTests.notFound("doc-1"));
        Assert.assertTrue(this.writtenEventIds().isEmpty());

        this.invokePrivate("periodicFlush");
        this.answer(1, WazuhEnrichedFindingServiceTests.found("doc-1"));

        Assert.assertEquals(List.of("doc-1"), this.writtenEventIds());
        Assert.assertEquals(1L, this.service.getRetriedReadCount());
        Assert.assertEquals(0L, this.service.getMissingCount());
    }

    /**
     * An event still not found after every read does not exist. It is reported as such, apart from a
     * failed read, and its finding is counted as left out.
     */
    public void testRead_eventNeverFound_reportedAsMissing() throws Exception {
        try (MockLogAppender appender =
                MockLogAppender.createForLoggers(LogManager.getLogger(WazuhEnrichedFindingService.class))) {
            LoggedLines warnings = new LoggedLines(Level.WARN);
            LoggedLines errors = new LoggedLines(Level.ERROR);
            appender.addExpectation(warnings);
            appender.addExpectation(errors);
            this.service.setMaxRetries(2);

            this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", "doc-1", EVENTS));
            this.answer(0, WazuhEnrichedFindingServiceTests.notFound("doc-1"));
            for (int read = 1; read <= 2; read++) {
                this.invokePrivate("periodicFlush");
                this.answer(read, WazuhEnrichedFindingServiceTests.notFound("doc-1"));
            }

            Assert.assertEquals("The first read plus two more", 3, this.sentMultiGets.size());
            Assert.assertEquals(2L, this.service.getRetriedReadCount());
            Assert.assertEquals(1L, this.service.getMissingCount());
            Assert.assertEquals(0L, this.service.getUnreadCount());
            Assert.assertTrue(this.writtenEventIds().isEmpty());
            Assert.assertTrue("A missing event is not a failed read", errors.lines.isEmpty());
            Assert.assertEquals(3, warnings.lines.size());
            MatcherAssert.assertThat(
                    warnings.lines.get(0),
                    containsString("Could not read 1 triggering events, reading them again"));
            MatcherAssert.assertThat(warnings.lines.get(0), containsString(EVENTS + "/doc-1: not found"));
            MatcherAssert.assertThat(
                    warnings.lines.get(2), containsString("1 triggering events do not exist"));
            MatcherAssert.assertThat(warnings.lines.get(2), containsString("(total so far: 1)"));

            this.invokePrivate("periodicFlush");
            Assert.assertEquals("Nothing is left to read", 3, this.sentMultiGets.size());
        }
    }

    /**
     * An event whose index no longer exists cannot be found by asking again: it is given up on at
     * once and reported as missing.
     */
    public void testRead_indexGone_givenUpAtOnceAsMissing() throws Exception {
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", "doc-1", EVENTS));
        this.answer(
                0, WazuhEnrichedFindingServiceTests.failed("doc-1", new IndexNotFoundException(EVENTS)));

        Assert.assertEquals(0L, this.service.getRetriedReadCount());
        Assert.assertEquals(1L, this.service.getMissingCount());
        Assert.assertEquals(0L, this.service.getUnreadCount());

        this.invokePrivate("periodicFlush");
        Assert.assertEquals(1, this.sentMultiGets.size());
    }

    /**
     * A read that keeps failing is given up on after the configured number of attempts, and the error
     * names the cause, so a failed read is never reported as an event not found.
     */
    public void testRead_retriesExhausted_errorNamesTheCause() throws Exception {
        try (MockLogAppender appender =
                MockLogAppender.createForLoggers(LogManager.getLogger(WazuhEnrichedFindingService.class))) {
            LoggedLines errors = new LoggedLines(Level.ERROR);
            appender.addExpectation(errors);
            this.service.setMaxRetries(2);

            this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", "doc-1", EVENTS));
            this.answer(
                    0,
                    WazuhEnrichedFindingServiceTests.failed(
                            "doc-1", WazuhEnrichedFindingServiceTests.rejected()));
            for (int read = 1; read <= 2; read++) {
                this.invokePrivate("periodicFlush");
                this.answer(
                        read,
                        WazuhEnrichedFindingServiceTests.failed(
                                "doc-1", WazuhEnrichedFindingServiceTests.rejected()));
            }

            Assert.assertEquals(2L, this.service.getRetriedReadCount());
            Assert.assertEquals(1L, this.service.getUnreadCount());
            Assert.assertEquals(0L, this.service.getMissingCount());
            Assert.assertEquals(1, errors.lines.size());
            MatcherAssert.assertThat(
                    errors.lines.get(0), containsString("Could not read 1 triggering events"));
            MatcherAssert.assertThat(errors.lines.get(0), containsString("(total so far: 1)"));
            MatcherAssert.assertThat(
                    errors.lines.get(0),
                    containsString(
                            EVENTS + "/doc-1: " + OpenSearchRejectedExecutionException.class.getName()));

            this.invokePrivate("periodicFlush");
            Assert.assertEquals("The given-up read is not sent again", 3, this.sentMultiGets.size());
        }
    }

    /** A read that failed for a permanent reason is given up on at once, with its cause. */
    public void testRead_permanentFailure_givenUpAtOnce() throws Exception {
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", "doc-1", EVENTS));
        this.answer(
                0,
                WazuhEnrichedFindingServiceTests.failed("doc-1", new IllegalArgumentException("bad id")));

        Assert.assertEquals(0L, this.service.getRetriedReadCount());
        Assert.assertEquals(1L, this.service.getUnreadCount());
    }

    /**
     * A MultiGet that failed as a whole reads every finding of the batch again, and only on the next
     * flush.
     */
    public void testRead_wholeMultiGetFailed_everyFindingReadAgain() throws Exception {
        this.service.enrich(
                WazuhEnrichedFindingServiceTests.finding("f-1", List.of("doc-1", "doc-2"), EVENTS));
        this.sentMultiGets.get(0).listener().onFailure(new NodeClosedException((DiscoveryNode) null));

        Assert.assertEquals(1L, this.service.getRetriedReadCount());
        Assert.assertEquals(1, this.sentMultiGets.size());

        this.invokePrivate("periodicFlush");
        Assert.assertEquals(
                List.of("doc-1", "doc-2"),
                WazuhEnrichedFindingServiceTests.docIds(this.sentMultiGets.get(1)));
        this.answer(
                1,
                WazuhEnrichedFindingServiceTests.found("doc-1"),
                WazuhEnrichedFindingServiceTests.found("doc-2"));
        Assert.assertEquals(List.of("doc-1", "doc-2"), this.writtenEventIds());
    }

    /**
     * A MultiGet rejected before {@code client.multiGet} returns puts its findings on the read retry
     * queue while the flush is processing the findings queue. They must still wait for the next flush
     * instead of being read again in the same one.
     */
    public void testRead_inlineFailure_readAgainOnlyOnNextFlush() throws Exception {
        this.inlineReadFailure = WazuhEnrichedFindingServiceTests.rejected();
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", "doc-1", EVENTS));
        Assert.assertEquals(1, this.sentMultiGets.size());
        Assert.assertEquals(1L, this.service.getRetriedReadCount());

        this.invokePrivate("periodicFlush");
        Assert.assertEquals("One read per flush", 2, this.sentMultiGets.size());

        this.inlineReadFailure = null;
        this.invokePrivate("periodicFlush");
        Assert.assertEquals(3, this.sentMultiGets.size());
        this.answer(2, WazuhEnrichedFindingServiceTests.found("doc-1"));
        Assert.assertEquals(List.of("doc-1"), this.writtenEventIds());
    }

    /**
     * The read retry queue is bounded by {@code enriched_findings_max_pending_retries}: past it, a
     * finding whose read failed is given up on and counted instead of queued.
     */
    public void testRead_retryQueueFull_overflowGivenUp() throws Exception {
        this.service.setMaxPendingRetries(1);
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", "doc-1", EVENTS));
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-2", "doc-2", EVENTS));
        this.answer(
                0,
                WazuhEnrichedFindingServiceTests.failed(
                        "doc-1", WazuhEnrichedFindingServiceTests.rejected()));
        this.answer(
                1,
                WazuhEnrichedFindingServiceTests.failed(
                        "doc-2", WazuhEnrichedFindingServiceTests.rejected()));

        Assert.assertEquals(1L, this.service.getRetriedReadCount());
        Assert.assertEquals(1L, this.service.getUnreadCount());

        this.invokePrivate("periodicFlush");
        Assert.assertEquals(
                List.of("doc-1"), WazuhEnrichedFindingServiceTests.docIds(this.sentMultiGets.get(2)));
    }

    /**
     * After a read rejected under load, no batch starts until the next flush: the findings that
     * arrive in the meantime wait instead of being sent to a node shedding load, and then leave in
     * one MultiGet with the finding read again. A finding that was not found does not pause the
     * reads.
     */
    public void testRead_transientFailurePausesBatchesUntilNextFlush() throws Exception {
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", "doc-1", EVENTS));
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-2", "doc-2", EVENTS));
        this.answer(0, WazuhEnrichedFindingServiceTests.notFound("doc-1"));
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-3", "doc-3", EVENTS));
        Assert.assertEquals("A miss does not pause the reads", 3, this.sentMultiGets.size());

        this.answer(
                1,
                WazuhEnrichedFindingServiceTests.failed(
                        "doc-2", WazuhEnrichedFindingServiceTests.rejected()));
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-4", "doc-4", EVENTS));
        this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-5", "doc-5", EVENTS));
        this.answer(2, WazuhEnrichedFindingServiceTests.found("doc-3"));
        Assert.assertEquals("No batch starts after the rejection", 3, this.sentMultiGets.size());

        this.invokePrivate("periodicFlush");
        Assert.assertEquals(4, this.sentMultiGets.size());
        Assert.assertEquals(
                List.of("doc-4", "doc-5", "doc-1", "doc-2"),
                WazuhEnrichedFindingServiceTests.docIds(this.sentMultiGets.get(3)));
    }

    /** With retries disabled, an event not read is given up on straight away. */
    public void testRead_retriesDisabled_givenUpAtOnce() throws Exception {
        this.service.setMaxRetries(0);
        this.service.enrich(
                WazuhEnrichedFindingServiceTests.finding("f-1", List.of("doc-1", "doc-2"), EVENTS));
        this.answer(
                0,
                WazuhEnrichedFindingServiceTests.notFound("doc-1"),
                WazuhEnrichedFindingServiceTests.failed(
                        "doc-2", WazuhEnrichedFindingServiceTests.rejected()));

        Assert.assertEquals(0L, this.service.getRetriedReadCount());
        Assert.assertEquals(1L, this.service.getMissingCount());
        Assert.assertEquals(1L, this.service.getUnreadCount());
    }

    /**
     * A batch whose events all fail to read is reported in one line, whatever its size, and the line
     * stays short: it lists the first events and counts the rest.
     */
    public void testRead_failedBatch_reportedInOneLine() throws Exception {
        try (MockLogAppender appender =
                MockLogAppender.createForLoggers(LogManager.getLogger(WazuhEnrichedFindingService.class))) {
            LoggedLines warnings = new LoggedLines(Level.WARN);
            appender.addExpectation(warnings);
            List<String> docIds = new ArrayList<>();
            for (int i = 1; i <= 12; i++) {
                docIds.add("doc-" + i);
            }
            this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", docIds, EVENTS));
            MultiGetItemResponse[] items =
                    docIds.stream()
                            .map(
                                    id ->
                                            WazuhEnrichedFindingServiceTests.failed(
                                                    id, WazuhEnrichedFindingServiceTests.rejected()))
                            .toArray(MultiGetItemResponse[]::new);
            this.answer(0, items);

            Assert.assertEquals(1, warnings.lines.size());
            MatcherAssert.assertThat(
                    warnings.lines.get(0), containsString("Could not read 12 triggering events"));
            MatcherAssert.assertThat(warnings.lines.get(0), containsString(EVENTS + "/doc-10: "));
            MatcherAssert.assertThat(warnings.lines.get(0), containsString(" and 2 more"));
            Assert.assertFalse(warnings.lines.get(0).contains(EVENTS + "/doc-11: "));
        }
    }

    /** Closing the service counts the findings it discards while they wait to read their events. */
    public void testClose_reportsFindingsWaitingToReadTheirEvents() throws Exception {
        try (MockLogAppender appender =
                MockLogAppender.createForLoggers(LogManager.getLogger(WazuhEnrichedFindingService.class))) {
            LoggedLines warnings = new LoggedLines(Level.WARN);
            appender.addExpectation(warnings);
            this.service.enrich(WazuhEnrichedFindingServiceTests.finding("f-1", "doc-1", EVENTS));
            this.answer(
                    0,
                    WazuhEnrichedFindingServiceTests.failed(
                            "doc-1", new NodeClosedException((DiscoveryNode) null)));

            this.service.close();

            MatcherAssert.assertThat(
                    warnings.lines.get(warnings.lines.size() - 1),
                    containsString("1 waiting to read their triggering events again"));
        }
    }

    /** Events not found and transient read failures are read again; the rest are not. */
    public void testIsRetryableRead() {
        Assert.assertTrue("Not found", WazuhEnrichedFindingService.isRetryableRead(null));
        Assert.assertTrue(
                "A rejection on the shard's node arrives wrapped",
                WazuhEnrichedFindingService.isRetryableRead(WazuhEnrichedFindingServiceTests.rejected()));
        Assert.assertTrue(
                WazuhEnrichedFindingService.isRetryableRead(
                        new NoShardAvailableActionException(null, "no copy available")));
        Assert.assertTrue(
                WazuhEnrichedFindingService.isRetryableRead(new NodeClosedException((DiscoveryNode) null)));

        Assert.assertFalse(
                WazuhEnrichedFindingService.isRetryableRead(new IndexNotFoundException(EVENTS)));
        Assert.assertFalse(
                WazuhEnrichedFindingService.isRetryableRead(new IllegalArgumentException("bad id")));
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

    /** Concrete index of the triggering events the read tests use. */
    private static final String EVENTS = ".ds-wazuh-events-v5-system-activity-000001";

    /** A finding over several source documents of one index, without rules. */
    private static Finding finding(String id, List<String> docIds, String index) {
        return new Finding(
                id,
                docIds,
                docIds,
                "monitor-1",
                "monitor-name",
                index,
                Collections.emptyList(),
                Instant.now(),
                "high");
    }

    /** An event of {@link #EVENTS} that exists, with a valid integration category. */
    private static MultiGetItemResponse found(String docId) {
        try {
            Map<String, Object> source =
                    Map.of("wazuh", Map.of("integration", Map.of("category", "system-activity")));
            BytesReference bytes = BytesReference.bytes(XContentFactory.jsonBuilder().map(source));
            return new MultiGetItemResponse(
                    new GetResponse(new GetResult(EVENTS, docId, 0, 1, 1, true, bytes, null, null)), null);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    /** An event of {@link #EVENTS} that the copy read does not hold. */
    private static MultiGetItemResponse notFound(String docId) {
        return new MultiGetItemResponse(
                new GetResponse(
                        new GetResult(
                                EVENTS,
                                docId,
                                SequenceNumbers.UNASSIGNED_SEQ_NO,
                                SequenceNumbers.UNASSIGNED_PRIMARY_TERM,
                                -1,
                                false,
                                null,
                                null,
                                null)),
                null);
    }

    /** An event of {@link #EVENTS} whose read failed. */
    private static MultiGetItemResponse failed(String docId, Exception failure) {
        return new MultiGetItemResponse(null, new MultiGetResponse.Failure(EVENTS, docId, failure));
    }

    /** A shard read rejected by a full {@code get} pool, as it reaches the coordinating node. */
    private static RemoteTransportException rejected() {
        return new RemoteTransportException(
                "[node-1][indices:data/read/mget[shard][s]]",
                new OpenSearchRejectedExecutionException("rejected execution of get on node-1"));
    }

    /** Completes the {@code index}-th source MultiGet with the given items, in request order. */
    private void answer(int index, MultiGetItemResponse... items) {
        this.sentMultiGets.get(index).listener().onResponse(new MultiGetResponse(items));
    }

    /**
     * Ids of the triggering events of every enriched finding sent for writing or waiting to be, in
     * the order they were built.
     */
    @SuppressWarnings("unchecked")
    private List<String> writtenEventIds() throws Exception {
        List<IndexRequest> requests = new ArrayList<>();
        for (SentBulk bulk : this.sentBulks) {
            bulk.request().requests().forEach(request -> requests.add((IndexRequest) request));
        }
        requests.addAll(this.pendingRequests());
        return requests.stream()
                .map(
                        request ->
                                (String) ((Map<String, Object>) request.sourceAsMap().get("event")).get("doc_id"))
                .toList();
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

    public void testSetMaxPending_updatesField() throws Exception {
        Field field = WazuhEnrichedFindingService.class.getDeclaredField("maxPending");
        field.setAccessible(true);

        service.setMaxPending(500);
        assertEquals(500, field.get(service));

        service.setMaxPending(1);
        assertEquals(1, field.get(service));
    }

    /**
     * The findings queue holds at most {@code enriched_findings_max_pending} findings. Past that, a
     * finding is refused and counted instead of queued: it never reaches {@code wazuh-findings-v5-*},
     * so the count is what makes the loss visible. A place frees up as soon as a waiting finding is
     * taken into a batch.
     */
    public void testFindingsQueueFull_refusesAndCountsOverflow() {
        service.setMaxInFlight(1);
        service.setMaxPending(2);

        for (int i = 1; i <= 5; i++) {
            service.enrich(finding("finding-" + i, "doc-" + i, "wazuh-events-v5-test"));
        }

        assertEquals(
                "finding-1 is in flight, 2 and 3 wait, 4 and 5 are refused",
                2L,
                service.getRejectedCount());
        assertEquals(1, sentMultiGets.size());

        sentMultiGets.get(0).listener().onFailure(new RuntimeException("source lookup failed"));
        assertEquals("the waiting findings leave the queue in one batch", 2, sentMultiGets.size());
        assertEquals(List.of("doc-2", "doc-3"), docIds(sentMultiGets.get(1)));

        service.enrich(finding("finding-6", "doc-6", "wazuh-events-v5-test"));
        assertEquals("the queue has room again", 2L, service.getRejectedCount());
    }

    /** A disabled pipeline queues nothing, so it refuses nothing either. */
    public void testDisabled_neitherQueuesNorRefuses() {
        service.setEnabled(false);
        service.setMaxPending(1);

        for (int i = 1; i <= 3; i++) {
            service.enrich(finding("finding-" + i, "doc-" + i, "wazuh-events-v5-test"));
        }

        assertEquals(0L, service.getRejectedCount());
        assertTrue(sentMultiGets.isEmpty());
    }

    /**
     * Records the formatted messages the enrichment service logs at one level, so a test can assert
     * how many lines a loss produced and what each one says.
     */
    private static final class LoggedLines implements MockLogAppender.LoggingExpectation {
        private final Level level;
        private final List<String> lines = new CopyOnWriteArrayList<>();

        LoggedLines(Level level) {
            this.level = level;
        }

        @Override
        public void match(LogEvent event) {
            if (event.getLevel().equals(this.level)
                    && event.getLoggerName().equals(WazuhEnrichedFindingService.class.getName())) {
                this.lines.add(event.getMessage().getFormattedMessage());
            }
        }

        @Override
        public void assertMatched() {}
    }

    /**
     * Refused findings are reported by the periodic flush: one ERROR per flush that follows a
     * refusal, carrying the number refused since the previous report and the running total. Every
     * refusal is reported, however many follow the first one, and a flush with nothing new to report
     * logs nothing.
     */
    public void testRefusals_reportedByEachFlushWithTheCountSinceTheLastReport() throws Exception {
        try (MockLogAppender appender =
                MockLogAppender.createForLoggers(LogManager.getLogger(WazuhEnrichedFindingService.class))) {
            LoggedLines errors = new LoggedLines(Level.ERROR);
            appender.addExpectation(errors);
            service.setMaxInFlight(1);
            service.setMaxPending(2);

            // finding-1 is in flight, 2 and 3 wait, 4 to 6 are refused.
            for (int i = 1; i <= 6; i++) {
                service.enrich(finding("finding-" + i, "doc-" + i, "wazuh-events-v5-test"));
            }
            invokePrivate("periodicFlush");
            assertEquals(1, errors.lines.size());
            assertThat(errors.lines.get(0), containsString("Findings refused since the last report: 3"));
            assertThat(errors.lines.get(0), containsString("Total findings lost so far: 3"));

            invokePrivate("periodicFlush");
            assertEquals("a flush with no new refusal logs nothing", 1, errors.lines.size());

            for (int i = 7; i <= 8; i++) {
                service.enrich(finding("finding-" + i, "doc-" + i, "wazuh-events-v5-test"));
            }
            invokePrivate("periodicFlush");
            assertEquals(2, errors.lines.size());
            assertThat(errors.lines.get(1), containsString("Findings refused since the last report: 2"));
            assertThat(errors.lines.get(1), containsString("Total findings lost so far: 5"));
        }
    }

    /**
     * A node that stops while findings still wait for enrichment discards them. Closing the service
     * reports the refusals no flush has reported yet and the findings it discards, and a second close
     * reports nothing more.
     */
    public void testClose_reportsUnreportedRefusalsAndDiscardedFindings() throws Exception {
        try (MockLogAppender appender =
                MockLogAppender.createForLoggers(LogManager.getLogger(WazuhEnrichedFindingService.class))) {
            LoggedLines errors = new LoggedLines(Level.ERROR);
            LoggedLines warnings = new LoggedLines(Level.WARN);
            appender.addExpectation(errors);
            appender.addExpectation(warnings);
            service.setMaxInFlight(1);
            service.setMaxPending(2);

            // finding-1 is in flight, 2 and 3 wait, 4 is refused.
            for (int i = 1; i <= 4; i++) {
                service.enrich(finding("finding-" + i, "doc-" + i, "wazuh-events-v5-test"));
            }
            service.close();
            service.close();

            assertEquals(1, errors.lines.size());
            assertThat(errors.lines.get(0), containsString("Findings refused since the last report: 1"));
            assertEquals(1, warnings.lines.size());
            assertThat(warnings.lines.get(0), containsString("2 waiting for enrichment"));
        }
    }

    private static List<String> docIds(SentMultiGet multiGet) {
        return multiGet.request().getItems().stream().map(MultiGetRequest.Item::id).toList();
    }

    public void testSetFlushInterval_reschedulesTask() {
        service.setFlushInterval(3);
        service.setFlushInterval(60);
    }
}
