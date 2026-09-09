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

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.core.action.ActionListener;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.internal.InternalSearchResponse;
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
        return SigmaRule.fromYaml(yamlWithId(id, title, detection), true);
    }

    private static String yaml(String title, String detection) {
        return yamlWithId("11111111-1111-1111-1111-111111111111", title, detection);
    }

    private static String yamlWithId(String id, String title, String detection) {
        return String.join(
                "\n",
                "title: " + title,
                "id: " + id,
                "status: test",
                "logsource:",
                "    category: test",
                "detection:",
                detection,
                "level: high");
    }

    /** Pairs a rule with the YAML it came from, as the evaluator now expects. */
    private static PercolateRuleEvaluator.ParsedRule parsed(String title, String detection)
            throws Exception {
        return new PercolateRuleEvaluator.ParsedRule(rule(title, detection), yaml(title, detection));
    }

    /** Pairs a rule carrying an explicit id with its YAML. */
    private static PercolateRuleEvaluator.ParsedRule parsedWithId(
            String id, String title, String detection) throws Exception {
        return new PercolateRuleEvaluator.ParsedRule(
                ruleWithId(id, title, detection), yamlWithId(id, title, detection));
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
    private BulkRequest captureStoredQueries(List<PercolateRuleEvaluator.ParsedRule> rules) {
        Client client = mock(Client.class);
        ArgumentCaptor<BulkRequest> captor = ArgumentCaptor.forClass(BulkRequest.class);
        doAnswer(invocation -> null).when(client).bulk(captor.capture(), any());

        new PercolateRuleEvaluator(client, readyQueryIndex())
                .evaluate(
                        EVENT,
                        rules,
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
        PercolateRuleEvaluator.ParsedRule twoConditions =
                parsed(
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
        List<PercolateRuleEvaluator.ParsedRule> twins =
                List.of(
                        parsedWithId("aaaaaaaa-0000-0000-0000-000000000001", "Twin A", detection),
                        parsedWithId("aaaaaaaa-0000-0000-0000-000000000002", "Twin B", detection));

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
                        parsed("A", "    selection:\n        process.name: cmd.exe\n    condition: selection"));
        String idB =
                storedDocId(
                        parsed(
                                "B",
                                "    selection:\n        process.name: powershell.exe\n    condition: selection"));

        assertNotEquals("a different rule body must be a different document", idA, idB);
        assertEquals(
                "the id must be stable for the same content",
                idA,
                storedDocId(
                        parsed(
                                "A", "    selection:\n        process.name: cmd.exe\n    condition: selection")));
    }

    public void testStoredDocumentsAreCreatedNotOverwritten() throws Exception {
        // Content-addressed ids make an existing document byte-identical, so CREATE turns a repeat
        // call into a cheap conflict instead of re-parsing and re-extracting the query's terms.
        BulkRequest stored =
                captureStoredQueries(
                        List.of(
                                parsed(
                                        "Any",
                                        "    selection:\n        process.name: cmd.exe\n    condition: selection")));

        assertEquals(DocWriteRequest.OpType.CREATE, stored.requests().get(0).opType());
    }

    public void testStoredDocumentCarriesTheIntegrationAndRuleId() throws Exception {
        BulkRequest stored =
                captureStoredQueries(
                        List.of(
                                parsed(
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
                                parsed(
                                        "Any",
                                        "    selection:\n        process.name: cmd.exe\n    condition: selection")),
                        INTEGRATION_ID,
                        "test",
                        List.of("wazuh-events-v5-test"),
                        ActionListener.wrap(result -> {}, failure::set));

        assertNotNull("a non-object event must fail", failure.get());
        verifyNoInteractions(client);
        verifyNoInteractions(queryIndex);
    }

    public void testTheResponseCarriesOnlyTheContractFields() throws Exception {
        // The logtest response contract is status / rules_evaluated / rules_matched / matches.
        // Anything else — a skip count, a per-rule skip list — is outside it.
        JsonNode result =
                evaluateWithoutCluster(
                        List.of(
                                parsed(
                                        "Aggregation",
                                        "    selection:\n        process.name: cmd.exe\n"
                                                + "    condition: selection | count() > 5")));

        List<String> fields = new ArrayList<>();
        result.fieldNames().forEachRemaining(fields::add);
        assertEquals(List.of("status", "rules_evaluated", "rules_matched", "matches"), fields);
    }

    public void testARuleThatCannotBeEvaluatedIsSimplyNotAMatch() throws Exception {
        // A bucket-level condition counts documents over a window, and a percolator sees one
        // document, so the rule cannot be evaluated. It is left out of the matches rather than
        // reported, and the reason goes to the log.
        JsonNode result =
                evaluateWithoutCluster(
                        List.of(
                                parsed(
                                        "Aggregation",
                                        "    selection:\n        process.name: cmd.exe\n"
                                                + "    condition: selection | count() > 5")));

        assertEquals(1, result.get("rules_evaluated").asInt());
        assertEquals(0, result.get("rules_matched").asInt());
        assertTrue(result.get("matches").isEmpty());
    }

    public void testRulesTheCallerCouldNotParseAreNotCounted() throws Exception {
        // The caller logs and drops a rule it could not parse, so it never reaches the evaluator's
        // rule list and is not one of the rules the response reports as evaluated.
        Client client = mock(Client.class);
        AtomicReference<String> resultJson = new AtomicReference<>();

        new PercolateRuleEvaluator(client, mock(LogtestQueryIndex.class))
                .evaluate(
                        EVENT,
                        List.of(),
                        INTEGRATION_ID,
                        "test",
                        List.of("wazuh-events-v5-test"),
                        ActionListener.wrap(resultJson::set, e -> fail(e.getMessage())));

        JsonNode result = MAPPER.readTree(resultJson.get());
        assertEquals(0, result.get("rules_evaluated").asInt());
        assertEquals(0, result.get("rules_matched").asInt());
        assertTrue(result.get("matches").isEmpty());
        verifyNoInteractions(client);
    }

    /** Runs an evaluation that never reaches the cluster, and returns the parsed result. */
    private JsonNode evaluateWithoutCluster(List<PercolateRuleEvaluator.ParsedRule> rules)
            throws Exception {
        Client client = mock(Client.class);
        AtomicReference<String> resultJson = new AtomicReference<>();

        new PercolateRuleEvaluator(client, mock(LogtestQueryIndex.class))
                .evaluate(
                        EVENT,
                        rules,
                        INTEGRATION_ID,
                        "test",
                        List.of("wazuh-events-v5-test"),
                        ActionListener.wrap(resultJson::set, e -> fail(e.getMessage())));

        assertNotNull("nothing needed the cluster, so a result was expected", resultJson.get());
        verifyNoInteractions(client);
        return MAPPER.readTree(resultJson.get());
    }

    private String storedDocId(PercolateRuleEvaluator.ParsedRule rule) {
        return captureStoredQueries(List.of(rule)).requests().get(0).id();
    }

    public void testMatchedConditionsAreListedPerCondition() throws Exception {
        // The contract is one readable entry per condition, not a single compiled query. A rule with
        // two conditions therefore reports two entries, and none of them is a composed expression.
        PercolateRuleEvaluator.ParsedRule twoFields =
                parsed(
                        "Two Fields",
                        "    selection:\n        http.request.method: GET\n"
                                + "        url.original: /admin\n    condition: selection");

        List<String> described = describeMatch(twoFields);

        assertEquals(2, described.size());
        assertTrue(described.toString(), described.contains("http.request.method matched 'GET'"));
        assertTrue(described.toString(), described.contains("url.original matched '/admin'"));
        for (String condition : described) {
            assertFalse(
                    "a condition must not be a composed expression: " + condition,
                    condition.contains(" AND "));
        }
    }

    /**
     * Percolates one rule against a client that reports it as matching, and returns its conditions.
     */
    private List<String> describeMatch(PercolateRuleEvaluator.ParsedRule matching) throws Exception {
        Client client = mock(Client.class);
        AtomicReference<String> stored = new AtomicReference<>();
        doAnswer(
                        invocation -> {
                            BulkRequest request = invocation.getArgument(0);
                            stored.set(request.requests().get(0).id());
                            ActionListener<BulkResponse> listener = invocation.getArgument(1);
                            listener.onResponse(new BulkResponse(new BulkItemResponse[0], 1L));
                            return null;
                        })
                .when(client)
                .bulk(any(), any());
        doAnswer(
                        invocation -> {
                            ActionListener<SearchResponse> listener = invocation.getArgument(1);
                            listener.onResponse(searchHitting(stored.get()));
                            return null;
                        })
                .when(client)
                .search(any(), any());

        AtomicReference<String> result = new AtomicReference<>();
        new PercolateRuleEvaluator(client, readyQueryIndex())
                .evaluate(
                        EVENT,
                        List.of(matching),
                        INTEGRATION_ID,
                        "test",
                        List.of("wazuh-events-v5-test"),
                        ActionListener.wrap(result::set, e -> fail(e.getMessage())));

        JsonNode conditions =
                MAPPER.readTree(result.get()).get("matches").get(0).get("matched_conditions");
        List<String> out = new ArrayList<>();
        conditions.forEach(node -> out.add(node.asText()));
        return out;
    }

    /** A search response with one hit, as the percolator returns for a matching stored query. */
    private SearchResponse searchHitting(String docId) {
        SearchHit hit = new SearchHit(0, docId, null, null);
        SearchHits hits =
                new SearchHits(new SearchHit[] {hit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);
        return new SearchResponse(
                new InternalSearchResponse(hits, null, null, null, false, null, 1),
                null,
                1,
                1,
                0,
                1L,
                new ShardSearchFailure[0],
                SearchResponse.Clusters.EMPTY);
    }
}
