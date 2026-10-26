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

import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.BooleanClause;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.TermQuery;
import org.opensearch.test.OpenSearchTestCase;

import java.util.List;

/**
 * The correlation join puts event field values into a {@code query_string}. These tests parse the
 * clause it builds the way {@code query_string} does, with the classic Lucene parser and a keyword
 * field, and check that a value can only ever match itself.
 */
public class JoinEngineQueryStringTests extends OpenSearchTestCase {

    private static final String FIELD = "user.name";

    /** The clause JoinEngine builds for one category: {@code field:(v1 OR v2 ...)}. */
    private static Query parseJoin(List<String> values) throws Exception {
        StringBuilder qb = new StringBuilder(FIELD).append(":(");
        for (int i = 0; i < values.size(); ++i) {
            qb.append(JoinEngine.queryStringValue(values.get(i)));
            qb.append(i < values.size() - 1 ? " OR " : ")");
        }
        return new QueryParser(FIELD, new KeywordAnalyzer()).parse(qb.toString());
    }

    private static void assertMatchesOnlyItself(String value) throws Exception {
        assertEquals(new TermQuery(new Term(FIELD, value)), parseJoin(List.of(value)));
    }

    public void testPlainValue() throws Exception {
        assertMatchesOnlyItself("bob");
    }

    public void testWildcardIsLiteral() throws Exception {
        // Unescaped, "*" turns the clause into a wildcard matching every event with the field.
        assertMatchesOnlyItself("*");
        assertMatchesOnlyItself("adm?n*");
    }

    public void testOperatorsAreLiteral() throws Exception {
        assertMatchesOnlyItself("x OR *:*");
        assertMatchesOnlyItself("bob) OR " + FIELD + ":(*");
        assertMatchesOnlyItself("NOT bob");
        assertMatchesOnlyItself("OR");
        assertMatchesOnlyItself("a && b || !c");
        assertMatchesOnlyItself("+bob -alice");
        assertMatchesOnlyItself("/.*/");
        assertMatchesOnlyItself("bob~2");
        assertMatchesOnlyItself("[a TO z]");
    }

    public void testUnbalancedSyntaxDoesNotBreakTheQuery() throws Exception {
        // Unescaped, these fail the whole search, which drops every correlation of the category.
        assertMatchesOnlyItself("bob)");
        assertMatchesOnlyItself("(bob");
        assertMatchesOnlyItself("say \"hi");
        assertMatchesOnlyItself("trailing\\");
    }

    public void testWhitespaceStaysInOneTerm() throws Exception {
        assertMatchesOnlyItself("john smith");
    }

    public void testSeveralValuesStayAlternatives() throws Exception {
        Query query = parseJoin(List.of("bob", "*", "a OR b"));

        assertTrue(query instanceof BooleanQuery);
        List<BooleanClause> clauses = ((BooleanQuery) query).clauses();
        assertEquals(3, clauses.size());
        assertEquals(new TermQuery(new Term(FIELD, "bob")), clauses.get(0).query());
        assertEquals(new TermQuery(new Term(FIELD, "*")), clauses.get(1).query());
        assertEquals(new TermQuery(new Term(FIELD, "a OR b")), clauses.get(2).query());
        for (BooleanClause clause : clauses) {
            assertEquals(BooleanClause.Occur.SHOULD, clause.occur());
        }
    }
}
