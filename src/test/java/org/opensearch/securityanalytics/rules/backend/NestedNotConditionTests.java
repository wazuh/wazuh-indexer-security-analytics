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

import org.apache.lucene.analysis.core.WhitespaceAnalyzer;
import org.apache.lucene.index.memory.MemoryIndex;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.BooleanClause;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.BoostQuery;
import org.apache.lucene.search.MatchAllDocsQuery;
import org.apache.lucene.search.Query;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Checks what a compiled condition <em>matches</em>, not only how it is spelled.
 *
 * <p>Each condition is compiled with {@link OSQueryBackend}, parsed with the Lucene query parser
 * and run against every combination of the selections being true, false or about a missing field.
 * The result must equal the condition evaluated as Sigma defines it. Every boolean group of the
 * parsed query gets the same rewrite {@code QueryStringQueryParser} gives it on the cluster: a
 * group made only of negative clauses matches everything those clauses do not exclude.
 *
 * <p>Covers nested {@code not} at depth two and more, {@code not} over {@code and}/{@code or}
 * groups, {@code |exists: false}, {@code null}, missing fields and keywords
 * (wazuh/wazuh-indexer-security-analytics#350), in both backend configurations.
 */
public class NestedNotConditionTests extends OpenSearchTestCase {

    private static final String DEFAULT_FIELD = "keywords_field";

    /** Selections of the test rule. Each one is a variable of the truth table. */
    private static final String DETECTION =
            "                a:\n"
                    + "                    fa: a\n"
                    + "                b:\n"
                    + "                    fb: b\n"
                    + "                c:\n"
                    + "                    fc: c\n"
                    + "                sel:\n"
                    + "                    fs: s\n"
                    + "                f:\n"
                    + "                    fx|exists: false\n"
                    + "                n:\n"
                    + "                    fn: null\n"
                    + "                kw:\n"
                    + "                    - kw\n";

    /** A state of the truth table: the value each selection takes. */
    private record State(
            int a, int b, int c, boolean s, boolean fxPresent, boolean fnPresent, boolean kw) {
        // a, b, c: 0 = value matches, 1 = another value, 2 = field missing.
        boolean isA() {
            return a == 0;
        }

        boolean isB() {
            return b == 0;
        }

        boolean isC() {
            return c == 0;
        }

        boolean isF() {
            return !fxPresent;
        }

        boolean isN() {
            return !fnPresent;
        }

        Map<String, String> document() {
            Map<String, String> doc = new LinkedHashMap<>();
            putTri(doc, "fa", "a", a);
            putTri(doc, "fb", "b", b);
            putTri(doc, "fc", "c", c);
            doc.put("fs", s ? "s" : "other");
            if (fxPresent) {
                doc.put("fx", "present");
            }
            if (fnPresent) {
                doc.put("fn", "present");
            }
            doc.put(DEFAULT_FIELD, kw ? "kw" : "nothing");
            return doc;
        }

        private static void putTri(Map<String, String> doc, String field, String value, int state) {
            if (state == 0) {
                doc.put(field, value);
            } else if (state == 1) {
                doc.put(field, "other");
            }
        }
    }

    private static List<State> allStates() {
        List<State> states = new ArrayList<>();
        for (int a = 0; a < 3; a++) {
            for (int b = 0; b < 3; b++) {
                for (int c = 0; c < 3; c++) {
                    for (int bits = 0; bits < 16; bits++) {
                        states.add(
                                new State(
                                        a, b, c, (bits & 1) != 0, (bits & 2) != 0, (bits & 4) != 0, (bits & 8) != 0));
                    }
                }
            }
        }
        return states;
    }

    public void testNotOfNotSelection() throws Exception {
        assertMatchesSigma("not (not a)", State::isA);
    }

    public void testNotOfAndWithNegatedOperand() throws Exception {
        assertMatchesSigma("not (a and not b)", st -> !st.isA() || st.isB());
    }

    public void testNotOfOrWithNegatedOperand() throws Exception {
        assertMatchesSigma("not (a or not b)", st -> !st.isA() && st.isB());
    }

    public void testSelectionAndNotOfAndWithNegatedOperand() throws Exception {
        assertMatchesSigma("sel and not (a and not b)", st -> st.s() && (!st.isA() || st.isB()));
    }

    public void testNotOfNotOr() throws Exception {
        assertMatchesSigma("not (not (a or b))", st -> st.isA() || st.isB());
    }

    public void testNotOfNotAnd() throws Exception {
        assertMatchesSigma("not (not (a and b))", st -> st.isA() && st.isB());
    }

    public void testTripleNot() throws Exception {
        assertMatchesSigma("not (not (not a))", st -> !st.isA());
    }

    public void testNotAtDepthThreeOverGroups() throws Exception {
        assertMatchesSigma(
                "not (a and not (b or not c))", st -> !(st.isA() && !(st.isB() || !st.isC())));
    }

    public void testSelectionAndNotExistsFalse() throws Exception {
        assertMatchesSigma("sel and not f", st -> st.s() && !st.isF());
    }

    public void testNotOfNotExistsFalse() throws Exception {
        assertMatchesSigma("not (not f)", State::isF);
    }

    public void testNotOfAndWithNegatedExistsFalse() throws Exception {
        assertMatchesSigma("not (a and not f)", st -> !st.isA() || st.isF());
    }

    public void testNotNull() throws Exception {
        assertMatchesSigma("not n", st -> !st.isN());
    }

    public void testNotOfNotNull() throws Exception {
        assertMatchesSigma("not (not n)", State::isN);
    }

    public void testNotOfNotKeyword() throws Exception {
        assertMatchesSigma("not (not kw)", State::kw);
    }

    public void testNotOfKeywordAndNegatedSelection() throws Exception {
        assertMatchesSigma("not (kw and not b)", st -> !st.kw() || st.isB());
    }

    public void testControlSelectionAndNot() throws Exception {
        assertMatchesSigma("sel and not b", st -> st.s() && !st.isB());
    }

    public void testControlHandWrittenDeMorgan() throws Exception {
        assertMatchesSigma("(not a) or b", st -> !st.isA() || st.isB());
    }

    public void testControlNotOfOr() throws Exception {
        assertMatchesSigma("not (a or b)", st -> !st.isA() && !st.isB());
    }

    public void testControlNotOfAnd() throws Exception {
        assertMatchesSigma("not (a and b)", st -> !st.isA() || !st.isB());
    }

    public void testControlExistsFalse() throws Exception {
        assertMatchesSigma("sel and f", st -> st.s() && st.isF());
    }

    /**
     * Compiles {@code condition} in both backend configurations and checks the query against every
     * state of the truth table.
     */
    private void assertMatchesSigma(String condition, Predicate<State> sigma) throws Exception {
        for (OSQueryBackend backend :
                List.of(
                        new OSQueryBackend(Map.of(), false),
                        new OSQueryBackend(Map.of("unrelated", "mapped_unrelated"), true))) {
            String compiled =
                    backend.convertRule(SigmaRule.fromYaml(rule(condition), false)).get(0).toString();
            Query query;
            try {
                QueryParser parser = new QueryParser(DEFAULT_FIELD, new WhitespaceAnalyzer());
                parser.setAllowLeadingWildcard(true);
                query = fixNegativeGroups(parser.parse(compiled));
            } catch (ParseException e) {
                throw new AssertionError(
                        "condition [" + condition + "] compiled to an unparseable query [" + compiled + "]", e);
            }
            for (State state : allStates()) {
                boolean expected = sigma.test(state);
                boolean actual = matches(query, state.document());
                if (expected != actual) {
                    fail(
                            "condition ["
                                    + condition
                                    + "] compiled to ["
                                    + compiled
                                    + "] (parsed "
                                    + query
                                    + ") matches="
                                    + actual
                                    + " but Sigma says "
                                    + expected
                                    + " for document "
                                    + state.document());
                }
            }
        }
    }

    private static boolean matches(Query query, Map<String, String> document) throws IOException {
        MemoryIndex index = new MemoryIndex();
        WhitespaceAnalyzer analyzer = new WhitespaceAnalyzer();
        StringBuilder exists = new StringBuilder();
        for (Map.Entry<String, String> field : document.entrySet()) {
            index.addField(field.getKey(), field.getValue(), analyzer);
            exists.append(field.getKey()).append(' ');
        }
        index.addField("_exists_", exists.toString(), analyzer);
        // Counted, not scored: a group of filter and negative clauses matches with a score of 0.
        return index.createSearcher().count(query) > 0;
    }

    /**
     * Gives every purely negative boolean group a match-all clause, as {@code
     * Queries.fixNegativeQueryIfNeeded} does at each grouping of a query string on the cluster.
     */
    private static Query fixNegativeGroups(Query query) {
        if (query instanceof BoostQuery boost) {
            return new BoostQuery(fixNegativeGroups(boost.getQuery()), boost.getBoost());
        }
        if (!(query instanceof BooleanQuery bool)) {
            return query;
        }
        BooleanQuery.Builder builder = new BooleanQuery.Builder();
        builder.setMinimumNumberShouldMatch(bool.getMinimumNumberShouldMatch());
        boolean onlyNegative = !bool.clauses().isEmpty();
        for (BooleanClause clause : bool.clauses()) {
            builder.add(fixNegativeGroups(clause.query()), clause.occur());
            if (clause.occur() != BooleanClause.Occur.MUST_NOT) {
                onlyNegative = false;
            }
        }
        if (onlyNegative) {
            builder.add(new MatchAllDocsQuery(), BooleanClause.Occur.FILTER);
        }
        return builder.build();
    }

    private static String rule(String condition) {
        return "            title: Test\n"
                + "            id: 39f919f3-980b-4e6f-a975-8af7e507ef2b\n"
                + "            status: test\n"
                + "            level: critical\n"
                + "            description: Nested not\n"
                + "            author: Test\n"
                + "            date: 2026/11/26\n"
                + "            logsource:\n"
                + "                category: test_category\n"
                + "                product: test_product\n"
                + "            detection:\n"
                + DETECTION
                + "                condition: "
                + condition;
    }
}
