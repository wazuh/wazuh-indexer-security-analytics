/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Unit tests for {@link RuleDetectorSync}. */
public class RuleDetectorSyncTests extends OpenSearchTestCase {

    private Client client;

    /** The rebuilds asked of the client, each still waiting for its listener to be completed. */
    private List<ActionListener<IndexDetectorResponse>> issued;

    /** The detector of each rebuild, in the order they were issued. */
    private List<String> issuedFor;

    @Override
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        super.setUp();
        RuleDetectorSync.clearInFlightRebuilds();
        this.client = mock(Client.class);
        this.issued = new ArrayList<>();
        this.issuedFor = new ArrayList<>();
        doAnswer(
                        invocation -> {
                            IndexDetectorRequest request = invocation.getArgument(1);
                            this.issuedFor.add(request.getDetectorId());
                            this.issued.add((ActionListener<IndexDetectorResponse>) invocation.getArgument(2));
                            return null;
                        })
                .when(this.client)
                .execute(any(), any(), any());
    }

    @Override
    public void tearDown() throws Exception {
        RuleDetectorSync.clearInFlightRebuilds();
        super.tearDown();
    }

    private static Detector detector(String id) {
        Detector detector = mock(Detector.class);
        when(detector.getId()).thenReturn(id);
        return detector;
    }

    private void rebuild(Detector detector, String ruleId, Runnable onDone) {
        RuleDetectorSync.rebuildOneAtATime(
                this.client, detector, WriteRequest.RefreshPolicy.IMMEDIATE, ruleId, onDone);
    }

    public void testDetectorsReferencingRuleQuery_prePackaged_targetsNestedPath() {
        QueryBuilder q =
                RuleDetectorSync.detectorsReferencingRuleQuery("pre_packaged_rules", "rule-123");

        assertTrue(q instanceof NestedQueryBuilder);
        assertEquals(
                "detector.inputs.detector_input.pre_packaged_rules", ((NestedQueryBuilder) q).path());
    }

    public void testDetectorsReferencingRuleQuery_custom_targetsNestedPath() {
        QueryBuilder q = RuleDetectorSync.detectorsReferencingRuleQuery("custom_rules", "r1");

        assertTrue(q instanceof NestedQueryBuilder);
        assertEquals("detector.inputs.detector_input.custom_rules", ((NestedQueryBuilder) q).path());
    }

    // -----------------------------------------------------------------------
    // Which detectors are rebuilt
    // -----------------------------------------------------------------------

    /** A detectors-index search response holding the given detectors as its hits. */
    private static SearchResponse detectorHits(List<Detector> detectors) throws Exception {
        SearchHit[] hits = new SearchHit[detectors.size()];
        for (int i = 0; i < detectors.size(); i++) {
            XContentBuilder source =
                    detectors
                            .get(i)
                            .toXContentWithUser(
                                    XContentFactory.jsonBuilder(),
                                    new ToXContent.MapParams(Map.of("with_type", "true")));
            SearchHit hit = new SearchHit(i, "detector-" + i, Map.of(), Map.of());
            hit.sourceRef(BytesReference.bytes(source));
            hits[i] = hit;
        }
        SearchResponse response = mock(SearchResponse.class);
        when(response.getHits())
                .thenReturn(
                        new SearchHits(hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 1.0f));
        return response;
    }

    @SuppressWarnings("unchecked")
    private void searchReturns(SearchResponse response) {
        doAnswer(
                        invocation -> {
                            ((ActionListener<SearchResponse>) invocation.getArgument(1)).onResponse(response);
                            return null;
                        })
                .when(this.client)
                .search(any(), any());
    }

    private static Detector withSource(String source) {
        Detector detector = TestHelpers.randomDetector(List.of("rule-1"));
        detector.setSource(source);
        return detector;
    }

    /**
     * Every detector referencing the rule is rebuilt, whoever owns it.
     *
     * <p>Leaving the Content Manager's own detectors out looks safe, since its detector phase
     * rebuilds them from their integration document right after the rules phase. It is not: that
     * phase only sends integrations that still have an enabled rule, so an integration whose rules
     * are all disabled builds no request and the detector it already created is never touched. Its
     * workflow stays scheduled and its monitor keeps the queries compiled from the rules that were
     * just disabled. Measured on a single node: disabling all 123 rules of one integration left its
     * workflow enabled, running every two minutes, over a monitor still holding all 123 queries.
     *
     * <p>See wazuh/wazuh-indexer-plugins#1837.
     */
    public void testEveryReferencingDetectorIsRebuilt() throws Exception {
        this.searchReturns(
                detectorHits(List.of(withSource(Detector.STANDARD_SOURCE), withSource("custom"))));
        AtomicInteger done = new AtomicInteger();

        RuleDetectorSync.rebuildDetectorsForRule(
                this.client,
                TestHelpers.xContentRegistry(),
                "pre_packaged_rules",
                "rule-1",
                WriteRequest.RefreshPolicy.IMMEDIATE,
                ActionListener.wrap(v -> done.incrementAndGet(), e -> fail("it failed: " + e)));

        assertEquals("both detectors are rebuilt", 2, this.issued.size());
        this.issued.get(0).onResponse(null);
        this.issued.get(1).onResponse(null);
        assertEquals("and the caller is told once", 1, done.get());
    }

    // -----------------------------------------------------------------------
    // How the remaining rebuilds are issued
    // -----------------------------------------------------------------------

    /**
     * A caller that disables many rules of the same detector issues them in parallel. Only one
     * rebuild may be in flight, and the ones asked for meanwhile collapse into a single trailing
     * pass, since a rebuild recompiles the detector from the rules as they stand rather than from the
     * rule that triggered it.
     */
    public void testRebuildsOfOneDetectorAreCoalesced() {
        Detector detector = detector("d1");
        AtomicInteger done = new AtomicInteger();

        for (int i = 0; i < 90; i++) {
            this.rebuild(detector, "rule-" + i, done::incrementAndGet);
        }

        assertEquals("one rebuild in flight, not ninety", 1, this.issued.size());
        assertEquals("the eighty-nine coalesced callers are already done", 89, done.get());

        this.issued.get(0).onResponse(null);

        assertEquals("one trailing pass for everything asked meanwhile", 2, this.issued.size());
        assertEquals("the caller that started it waits for its own pass", 89, done.get());

        this.issued.get(1).onResponse(null);

        assertEquals("and nothing more", 2, this.issued.size());
        assertEquals(90, done.get());
    }

    /** A failed rebuild releases the detector, so the next change is not ignored. */
    public void testAFailedRebuildDoesNotBlockTheNextOne() {
        Detector detector = detector("d1");
        AtomicInteger done = new AtomicInteger();

        this.rebuild(detector, "rule-1", done::incrementAndGet);
        this.issued.get(0).onFailure(new IllegalStateException("workflow not found"));

        assertEquals("the failure completed the caller", 1, done.get());

        this.rebuild(detector, "rule-2", done::incrementAndGet);

        assertEquals("the detector is free again", 2, this.issued.size());
    }

    /** Different detectors are independent: one in flight does not hold up another. */
    public void testDifferentDetectorsRebuildInParallel() {
        AtomicInteger done = new AtomicInteger();

        this.rebuild(detector("d1"), "rule-1", done::incrementAndGet);
        this.rebuild(detector("d2"), "rule-1", done::incrementAndGet);
        this.rebuild(detector("d3"), "rule-1", done::incrementAndGet);

        assertEquals(3, this.issued.size());
        assertEquals(List.of("d1", "d2", "d3"), this.issuedFor);
        assertEquals("none of them is done yet", 0, done.get());
    }

    /**
     * A rebuild completes once, even when the caller's own completion throws. {@code
     * ActionListener.wrap} routes an exception thrown by the response arm into the failure arm, so
     * without a one-shot guard the detector would be released, or re-rebuilt, a second time, and the
     * caller would be counted down twice.
     */
    public void testACompletionThatThrowsIsNotRunTwice() {
        Detector detector = detector("d1");
        AtomicInteger done = new AtomicInteger();

        this.rebuild(
                detector,
                "rule-1",
                () -> {
                    done.incrementAndGet();
                    throw new IllegalStateException("the caller's listener threw");
                });

        this.issued.get(0).onResponse(null);

        assertEquals("the caller is counted down once", 1, done.get());
        assertEquals("and no second rebuild is issued", 1, this.issued.size());
    }

    /**
     * A dispatch that throws instead of calling the listener releases the detector. Otherwise it
     * would stay claimed for the lifetime of the node, and every later change to it would be
     * coalesced into a pass that never runs.
     */
    @SuppressWarnings("unchecked")
    public void testADispatchThatThrowsReleasesTheDetector() {
        AtomicInteger attempts = new AtomicInteger();
        doAnswer(
                        invocation -> {
                            if (attempts.incrementAndGet() == 1) {
                                throw new IllegalStateException("the node is closing");
                            }
                            IndexDetectorRequest request = invocation.getArgument(1);
                            this.issuedFor.add(request.getDetectorId());
                            this.issued.add((ActionListener<IndexDetectorResponse>) invocation.getArgument(2));
                            return null;
                        })
                .when(this.client)
                .execute(any(), any(), any());

        Detector detector = detector("d1");
        AtomicInteger done = new AtomicInteger();

        this.rebuild(detector, "rule-1", done::incrementAndGet);

        assertEquals("the caller is not left waiting on a request that was never sent", 1, done.get());
        assertTrue("nothing reached the client", this.issued.isEmpty());

        this.rebuild(detector, "rule-2", done::incrementAndGet);

        assertEquals("the detector is free, so the next change rebuilds it", 1, this.issued.size());
    }

    /** Two changes that do not overlap each get their own rebuild. */
    public void testSequentialRebuildsAreNotCoalesced() {
        Detector detector = detector("d1");
        AtomicInteger done = new AtomicInteger();

        this.rebuild(detector, "rule-1", done::incrementAndGet);
        this.issued.get(0).onResponse(null);
        assertEquals(1, done.get());

        this.rebuild(detector, "rule-2", done::incrementAndGet);
        this.issued.get(1).onResponse(null);

        assertEquals("one rebuild each", 2, this.issued.size());
        assertEquals(2, done.get());
    }
}
