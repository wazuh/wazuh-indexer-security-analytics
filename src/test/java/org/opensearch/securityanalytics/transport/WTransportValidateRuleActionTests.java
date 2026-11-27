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
package org.opensearch.securityanalytics.transport;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.rules.objects.WCSFieldValidator;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class WTransportValidateRuleActionTests extends OpenSearchTestCase {

    private static final WTransportValidateRuleAction.QueryLimits NO_LIMIT =
            new WTransportValidateRuleAction.QueryLimits(Integer.MAX_VALUE, false, 50);

    @Override
    public void tearDown() throws Exception {
        WCSFieldValidator.reset();
        super.tearDown();
    }

    private static String rule(String detection, String condition) {
        return "title: Validate\n"
                + "id: 26a8d32e-0838-5589-948c-501b5a301cf5\n"
                + "status: test\n"
                + "level: low\n"
                + "description: Validate\n"
                + "author: Wazuh\n"
                + "date: 2026/11/26\n"
                + "logsource:\n"
                + "  product: apache-http\n"
                + "detection:\n"
                + detection
                + "  condition: "
                + condition
                + "\n";
    }

    public void testValidStandardRuleReturnsItsQuery() {
        List<String> queries =
                WTransportValidateRuleAction.validate(
                        rule(
                                "  selection:\n"
                                        + "    url.original|contains: .git/\n"
                                        + "  _filt_a177600000_selection:\n"
                                        + "    user_agent.original|startswith: internal-scanner\n",
                                "(selection) and (not _filt_a177600000_selection)"),
                        Collections.emptyMap(),
                        false,
                        NO_LIMIT);

        assertEquals(
                List.of("(url.original: *.git\\/*) AND ((NOT user_agent.original: internal\\-scanner*))"),
                queries);
    }

    public void testValidCustomRuleIsCompiledWithItsFieldMappings() {
        List<String> queries =
                WTransportValidateRuleAction.validate(
                        rule("  selection:\n    url.original|contains: .git/\n", "selection"),
                        Map.of("url.original", "url.full"),
                        true,
                        NO_LIMIT);

        assertEquals(List.of("url.full: *.git\\/*"), queries);
    }

    public void testUndefinedIdentifierIsBadRequest() {
        SecurityAnalyticsException e =
                expectThrows(
                        SecurityAnalyticsException.class,
                        () ->
                                WTransportValidateRuleAction.validate(
                                        rule("  selection:\n    url.original: a\n", "selection and not missing"),
                                        Collections.emptyMap(),
                                        false,
                                        NO_LIMIT));

        assertEquals(RestStatus.BAD_REQUEST, e.status());
    }

    public void testFieldOutsideWcsIsBadRequest() {
        WCSFieldValidator.initFromFieldSet(Set.of("url.original"));

        SecurityAnalyticsException e =
                expectThrows(
                        SecurityAnalyticsException.class,
                        () ->
                                WTransportValidateRuleAction.validate(
                                        rule(
                                                "  selection:\n"
                                                        + "    url.original: a\n"
                                                        + "  _filt_a177600000_selection:\n"
                                                        + "    not.a.wcs.field: b\n",
                                                "(selection) and (not _filt_a177600000_selection)"),
                                        Collections.emptyMap(),
                                        false,
                                        NO_LIMIT));

        assertEquals(RestStatus.BAD_REQUEST, e.status());
        assertTrue(e.getMessage(), e.getMessage().contains("not.a.wcs.field"));
    }

    public void testQueryThatDoesNotParseIsBadRequest() {
        SecurityAnalyticsException e =
                expectThrows(
                        SecurityAnalyticsException.class,
                        () ->
                                WTransportValidateRuleAction.requireParses(
                                        "(url.original: a) AND ((NOT NOT _exists_: user.name))"));

        assertEquals(RestStatus.BAD_REQUEST, e.status());
        assertTrue(e.getMessage(), e.getMessage().contains("does not parse"));
    }

    public void testQueryThatParsesIsAccepted() {
        WTransportValidateRuleAction.requireParses(
                "(url.original: *.git\\/*) AND ((NOT user_agent.original: internal\\-scanner*))");
    }

    /** A rule that lists {@code count} source IP addresses. */
    private static String ipRule(int count) {
        StringBuilder detection = new StringBuilder("  selection:\n    source.ip:\n");
        for (int i = 0; i < count; i++) {
            detection.append("      - 10.30.0.").append(i).append('\n');
        }
        return rule(detection.toString(), "selection");
    }

    public void testQueryLongerThanTheLimitOnceStoredIsBadRequest() {
        String rule = ipRule(20);
        String query =
                WTransportValidateRuleAction.validate(rule, Collections.emptyMap(), false, NO_LIMIT).get(0);
        // Shorter than the limit as compiled, longer once each of its 20 fields gets 50 characters.
        WTransportValidateRuleAction.QueryLimits limits =
                new WTransportValidateRuleAction.QueryLimits(query.length() + 100, false, 50);

        SecurityAnalyticsException e =
                expectThrows(
                        SecurityAnalyticsException.class,
                        () ->
                                WTransportValidateRuleAction.validate(rule, Collections.emptyMap(), false, limits));

        assertEquals(RestStatus.BAD_REQUEST, e.status());
        assertTrue(e.getMessage(), e.getMessage().contains("search.query.max_query_string_length"));
        assertTrue(e.getMessage(), e.getMessage().contains(String.valueOf(query.length() + 20 * 50)));
    }

    public void testQueryThatFitsOnceStoredIsAccepted() {
        String rule = ipRule(20);
        String query =
                WTransportValidateRuleAction.validate(rule, Collections.emptyMap(), false, NO_LIMIT).get(0);
        WTransportValidateRuleAction.QueryLimits limits =
                new WTransportValidateRuleAction.QueryLimits(query.length() + 20 * 50, false, 50);

        assertEquals(
                List.of(query),
                WTransportValidateRuleAction.validate(rule, Collections.emptyMap(), false, limits));
    }

    public void testMonitorOnlyLimitAcceptsALongQuery() {
        WTransportValidateRuleAction.QueryLimits limits =
                new WTransportValidateRuleAction.QueryLimits(10, true, 50);

        assertEquals(
                1,
                WTransportValidateRuleAction.validate(ipRule(20), Collections.emptyMap(), false, limits)
                        .size());
    }

    public void testStoredLengthCountsEachFieldReference() {
        String query = "(url.original: a) OR (url.original: b) AND (NOT _exists_: user.name)";

        assertEquals(
                query.length() + 3 * 10,
                WTransportValidateRuleAction.storedLength(query, Set.of("url.original", "user.name"), 10));
    }

    public void testTooManyClausesNamesTheLimitAndQuotesTheQueryShort() {
        StringBuilder query = new StringBuilder("source.ip: 10.0.0.0");
        for (int i = 1; i <= 1100; i++) {
            query.append(" OR source.ip: 10.0.").append(i / 250).append('.').append(i % 250);
        }

        SecurityAnalyticsException e =
                expectThrows(
                        SecurityAnalyticsException.class,
                        () -> WTransportValidateRuleAction.requireParses(query.toString()));

        assertEquals(RestStatus.BAD_REQUEST, e.status());
        assertTrue(e.getMessage(), e.getMessage().contains("indices.query.bool.max_clause_count"));
        assertTrue(e.getMessage(), e.getMessage().length() < 600);
        assertTrue(e.getMessage(), e.getMessage().contains("(" + query.length() + " characters)"));
    }
}
