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
package org.opensearch.securityanalytics.rules.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Covers the parts of the evaluator that do not need a cluster: what it decides to store, how it
 * identifies the documents it stores, and what it refuses to evaluate at all.
 *
 * <p>The percolate search itself is left unstubbed on purpose — these tests assert on the bulk
 * request, which is where the decisions worth pinning are visible.
 */
public class PercolateRuleEvaluatorTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String INTEGRATION_ID = "integration-1";
    private static final String EVENT = "{\"process\": {\"name\": \"cmd.exe\"}}";

    private static SigmaRule rule(String title, String detection) throws Exception {
        return ruleWithId("11111111-1111-1111-1111-111111111111", title, detection);
    }

    private static SigmaRule ruleWithId(String id, String title, String detection) throws Exception {
        return SigmaRule.fromYaml(
                String.join(
                        "\n",
                        "title: " + title,
                        "id: " + id,
                        "status: test",
                        "logsource:",
                        "    category: test",
                        "detection:",
                        detection,
                        "level: high"),
                true);
    }

    /** A query index that reports itself ready, so the evaluator proceeds to store queries. */
    private LogtestQueryIndex readyQueryIndex() {
        LogtestQueryIndex queryIndex = mock(LogtestQueryIndex.class);
        doAnswer(
                        invocation -> {
                            ActionListener<LogtestQueryIndex.PreparedIndex> listener = invocation.getArgument(3);
                            listener.onResponse(new LogtestQueryIndex.PreparedIndex("query-index", null));
                            return null;
                        })
                .when(queryIndex)
                .ensureIndex(any(), any(), any(), any());
        return queryIndex;
    }

    /** Captures the bulk request the evaluator builds, without completing the call. */
    private BulkRequest captureStoredQueries(List<SigmaRule> rules) {
        Client client = mock(Client.class);
        ArgumentCaptor<BulkRequest> captor = ArgumentCaptor.forClass(BulkRequest.class);
        doAnswer(invocation -> null).when(client).bulk(captor.capture(), any());

        new PercolateRuleEvaluator(client, readyQueryIndex())
                .evaluate(
                        EVENT,
                        rules,
                        new ArrayList<>(),
                        INTEGRATION_ID,
                        "test",
                        List.of("wazuh-events-v5-test"),
                        ActionListener.wrap(result -> {}, e -> {}));

        return captor.getValue();
    }

    public void testRuleIdUsesTheRulesOwnId() throws Exception {
        assertEquals(
                "11111111-1111-1111-1111-111111111111",
                PercolateRuleEvaluator.ruleId(
                        rule("With Id", "    selection:\n        a: 1\n    condition: selection"), 3));
    }

    public void testRuleIdFallsBackToThePositionInTheRequest() {
        // Sigma makes `id` optional, and a percolator document still needs a key.
        assertEquals("rule_3", PercolateRuleEvaluator.ruleId(null, 3));
    }

    public void testOnlyTheFirstDetectionConditionIsStored() throws Exception {
        // A detector is built from rule.getQueries().get(0) alone, so percolating the other
        // conditions would report matches production cannot produce.
        SigmaRule twoConditions =
                rule(
                        "Two Conditions",
                        String.join(
                                "\n",
                                "    selection1:",
                                "        process.name: cmd.exe",
                                "    selection2:",
                                "        process.name: powershell.exe",
                                "    condition:",
                                "        - selection1",
                                "        - selection2"));

        BulkRequest stored = captureStoredQueries(List.of(twoConditions));

        assertEquals("only the first condition may be stored", 1, stored.requests().size());
        IndexRequest request = (IndexRequest) stored.requests().get(0);
        assertTrue(
                "the stored query must be the first condition",
                request.sourceAsMap().toString().contains("cmd.exe"));
        assertFalse(
                "the second condition must not be stored",
                request.sourceAsMap().toString().contains("powershell.exe"));
    }

    public void testRulesWithIdenticalDetectionEachGetTheirOwnDocument() throws Exception {
        // Several rules of one integration can legitimately carry the same detection, so they compile
        // to the same query. Keying the document only on that query collapses them into one document
        // and only one of them is ever reported as matching.
        String detection = "    selection:\n        process.name: cmd.exe\n    condition: selection";
        List<SigmaRule> twins =
                List.of(
                        ruleWithId("aaaaaaaa-0000-0000-0000-000000000001", "Twin A", detection),
                        ruleWithId("aaaaaaaa-0000-0000-0000-000000000002", "Twin B", detection));

        BulkRequest stored = captureStoredQueries(twins);

        assertEquals("both rules must be stored", 2, stored.requests().size());
        assertNotEquals(
                "identical detection must not collapse two rules into one document",
                stored.requests().get(0).id(),
                stored.requests().get(1).id());
    }

    public void testDocumentIdsAreContentAddressed() throws Exception {
        // Same rule id, different rule body: two logtest calls must not collide on one document.
        String idA =
                storedDocId(
                        rule("A", "    selection:\n        process.name: cmd.exe\n    condition: selection"));
        String idB =
                storedDocId(
                        rule(
                                "B",
                                "    selection:\n        process.name: powershell.exe\n    condition: selection"));

        assertNotEquals("a different rule body must be a different document", idA, idB);
        assertEquals(
                "the id must be stable for the same content",
                idA,
                storedDocId(
                        rule("A", "    selection:\n        process.name: cmd.exe\n    condition: selection")));
    }

    public void testStoredDocumentsAreCreatedNotOverwritten() throws Exception {
        // Content-addressed ids make an existing document byte-identical, so CREATE turns a repeat
        // call into a cheap conflict instead of re-parsing and re-extracting the query's terms.
        BulkRequest stored =
                captureStoredQueries(
                        List.of(
                                rule(
                                        "Any",
                                        "    selection:\n        process.name: cmd.exe\n    condition: selection")));

        assertEquals(DocWriteRequest.OpType.CREATE, stored.requests().get(0).opType());
    }

    public void testStoredDocumentCarriesTheIntegrationAndRuleId() throws Exception {
        BulkRequest stored =
                captureStoredQueries(
                        List.of(
                                rule(
                                        "Any",
                                        "    selection:\n        process.name: cmd.exe\n    condition: selection")));

        IndexRequest request = (IndexRequest) stored.requests().get(0);
        assertEquals(INTEGRATION_ID, request.sourceAsMap().get(LogtestQueryIndex.INTEGRATION_ID_FIELD));
        assertEquals(
                "11111111-1111-1111-1111-111111111111",
                request.sourceAsMap().get(LogtestQueryIndex.RULE_ID_FIELD));
    }

    public void testAnEventThatIsNotAJsonObjectIsRejectedBeforeAnythingIsWritten() throws Exception {
        // percolate_ext only parses its document when the search is rewritten, which is after every
        // compiled query has been written. So this has to fail first.
        Client client = mock(Client.class);
        LogtestQueryIndex queryIndex = mock(LogtestQueryIndex.class);
        AtomicReference<Exception> failure = new AtomicReference<>();

        new PercolateRuleEvaluator(client, queryIndex)
                .evaluate(
                        "\"just a string\"",
                        List.of(
                                rule(
                                        "Any",
                                        "    selection:\n        process.name: cmd.exe\n    condition: selection")),
                        new ArrayList<>(),
                        INTEGRATION_ID,
                        "test",
                        List.of("wazuh-events-v5-test"),
                        ActionListener.wrap(result -> {}, failure::set));

        assertNotNull("a non-object event must fail", failure.get());
        verifyNoInteractions(client);
        verifyNoInteractions(queryIndex);
    }

    public void testAnAggregationRuleIsReportedAsSkipped() throws Exception {
        // A percolator sees one document; a bucket-level condition counts documents over a window.
        SigmaRule aggregation =
                rule(
                        "Aggregation",
                        "    selection:\n        process.name: cmd.exe\n    condition: selection | count() > 5");

        JsonNode result = evaluateWithoutCluster(List.of(aggregation));

        assertEquals(1, result.get("rules_evaluated").asInt());
        assertEquals(0, result.get("rules_matched").asInt());
        assertEquals(1, result.get("rules_skipped").asInt());
        assertTrue(result.get("skipped").get(0).get("reason").asText().contains("aggregation"));
    }

    public void testRulesTheCallerCouldNotParseAreCarriedIntoTheResult() throws Exception {
        List<PercolateRuleEvaluator.SkippedRule> alreadySkipped =
                List.of(
                        new PercolateRuleEvaluator.SkippedRule(null, "rule_0", "the rule could not be parsed"));
        Client client = mock(Client.class);
        AtomicReference<String> resultJson = new AtomicReference<>();

        new PercolateRuleEvaluator(client, mock(LogtestQueryIndex.class))
                .evaluate(
                        EVENT,
                        List.of(),
                        new ArrayList<>(alreadySkipped),
                        INTEGRATION_ID,
                        "test",
                        List.of("wazuh-events-v5-test"),
                        ActionListener.wrap(resultJson::set, e -> fail(e.getMessage())));

        JsonNode result = MAPPER.readTree(resultJson.get());
        assertEquals(
                "an unparseable rule was still a rule the request covered",
                1,
                result.get("rules_evaluated").asInt());
        assertEquals(1, result.get("rules_skipped").asInt());
        assertEquals("rule_0", result.get("skipped").get(0).get("rule").get("id").asText());
        verifyNoInteractions(client);
    }

    /** Runs an evaluation that never reaches the cluster, and returns the parsed result. */
    private JsonNode evaluateWithoutCluster(List<SigmaRule> rules) throws Exception {
        Client client = mock(Client.class);
        AtomicReference<String> resultJson = new AtomicReference<>();

        new PercolateRuleEvaluator(client, mock(LogtestQueryIndex.class))
                .evaluate(
                        EVENT,
                        rules,
                        new ArrayList<>(),
                        INTEGRATION_ID,
                        "test",
                        List.of("wazuh-events-v5-test"),
                        ActionListener.wrap(resultJson::set, e -> fail(e.getMessage())));

        assertNotNull("nothing needed the cluster, so a result was expected", resultJson.get());
        verifyNoInteractions(client);
        return MAPPER.readTree(resultJson.get());
    }

    private String storedDocId(SigmaRule rule) {
        return captureStoredQueries(List.of(rule)).requests().get(0).id();
    }

    /** Builds a bulk response whose single item failed with the given status. */
    private BulkResponse failedBulk(String docId, RestStatus status, String message) {
        BulkItemResponse.Failure failure =
                new BulkItemResponse.Failure("idx", docId, new OpenSearchStatusException(message, status));
        return new BulkResponse(
                new BulkItemResponse[] {new BulkItemResponse(0, DocWriteRequest.OpType.CREATE, failure)},
                1L);
    }

    /** Runs one rule through the evaluator against a client whose bulk write fails as given. */
    private JsonNode skipReasonFor(RestStatus status, String message) throws Exception {
        Client client = mock(Client.class);
        doAnswer(
                        invocation -> {
                            BulkRequest request = invocation.getArgument(0);
                            ActionListener<BulkResponse> listener = invocation.getArgument(1);
                            String id = request.requests().get(0).id();
                            listener.onResponse(failedBulk(id, status, message));
                            return null;
                        })
                .when(client)
                .bulk(any(), any());
        AtomicReference<String> result = new AtomicReference<>();
        new PercolateRuleEvaluator(client, readyQueryIndex())
                .evaluate(
                        EVENT,
                        List.of(
                                rule(
                                        "Any",
                                        "    selection:\n        process.name: cmd.exe\n    condition: selection")),
                        new ArrayList<>(),
                        INTEGRATION_ID,
                        "test",
                        List.of("wazuh-events-v5-test"),
                        ActionListener.wrap(result::set, e -> fail(e.getMessage())));
        assertNotNull("the evaluator should have answered", result.get());
        return MAPPER.readTree(result.get()).get("skipped").get(0);
    }

    public void testAQueryThePercolatorRefusedBlamesTheRule() throws Exception {
        // BAD_REQUEST means the percolator read the query and rejected it, so a detector — which
        // parses the same query the same way — cannot match the rule either.
        JsonNode skipped =
                skipReasonFor(RestStatus.BAD_REQUEST, "failed to parse: No field mapping can be found");
        String reason = skipped.get("reason").asText();

        assertTrue(reason, reason.contains("a deployed detector cannot match it either"));
    }

    public void testAnUnusableIndexDoesNotBlameTheRule() throws Exception {
        // A write block, a closed index or a node failure means the query never reached the
        // percolator. Claiming the rule is at fault would be wrong: the detector's query index is a
        // different index and may well match.
        JsonNode skipped =
                skipReasonFor(RestStatus.FORBIDDEN, "blocked by: [FORBIDDEN/8/index write (api)]");
        String reason = skipped.get("reason").asText();

        assertFalse(reason, reason.contains("a deployed detector cannot match it either"));
        assertTrue(reason, reason.contains("limitation of logtest"));
        assertTrue(reason, reason.contains("may still match it"));
    }
}
