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
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.condition.ConditionType;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A rule whose condition or regular expression is too large to compile is refused as a bad request,
 * and never surfaces as a {@link StackOverflowError}, which would halt the node.
 */
public class SigmaRuleSizeLimitsTests extends OpenSearchTestCase {

    /** The stack every OpenSearch thread runs with: {@code -Xss1m} in the shipped jvm.options. */
    private static final long PRODUCTION_STACK = 1L << 20;

    private static String rule(String condition, String extraDetection) {
        return "title: size limits\n"
                + "id: 5f92fff9-82e2-48ab-8fc1-8b133556a551\n"
                + "status: test\n"
                + "level: low\n"
                + "logsource:\n"
                + "  product: test\n"
                + "detection:\n"
                + "  sel:\n"
                + "    event.action: login\n"
                + extraDetection
                + "  condition: '"
                + condition
                + "'\n";
    }

    private static void assertRefusedAsBadRequest(SigmaRule rule, String reason) {
        assertNotNull(rule.getErrors());
        assertFalse("the rule should have been refused", rule.getErrors().getErrors().isEmpty());
        String message = rule.getErrors().getErrors().get(0).getMessage();
        assertTrue(message, message.contains(reason));
        // The transport actions answer a refused rule with this wrapper; its status is the HTTP one.
        assertEquals(
                RestStatus.BAD_REQUEST, SecurityAnalyticsException.wrap(rule.getErrors()).status());
    }

    public void testLongChainedConditionIsRefusedAsABadRequest() {
        // 3000 operands: past the depth at which converting it would overflow a 1 MiB stack.
        String condition = String.join(" and ", Collections.nCopies(3000, "sel"));
        assertRefusedAsBadRequest(
                SigmaRule.fromYaml(rule(condition, ""), true), "Sigma condition is " + condition.length());
    }

    public void testConditionWithTooManyOperatorsIsRefusedAsABadRequest() {
        String condition =
                String.join(" or ", Collections.nCopies(SigmaCondition.MAX_CONDITION_OPERATORS + 2, "sel"));
        assertRefusedAsBadRequest(SigmaRule.fromYaml(rule(condition, ""), true), "logical operators");
    }

    public void testDeeplyNestedRegularExpressionIsRefusedAsABadRequest() {
        // The deepest nesting that still fits OpenSearch's default 1000-character regex cap.
        String regex = "(".repeat(495) + "a" + ")".repeat(495);
        String re = "  re:\n    event.action|re: '" + regex + "'\n";
        assertRefusedAsBadRequest(
                SigmaRule.fromYaml(rule("sel and re", re), true), "opening parentheses");
    }

    public void testLargestAcceptedConditionConvertsOnAQuarterOfTheStack() throws Exception {
        // The size limits must leave a wide margin, not merely fit: the request thread has already
        // used part of its stack by the time the rule is converted.
        String condition = SigmaConditionTests.largestAcceptedCondition("sel");
        SigmaRule rule = SigmaRule.fromYaml(rule(condition, ""), true);
        assertTrue(rule.getErrors().getErrors().isEmpty());

        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<List<Object>> queries = new AtomicReference<>();
        Thread thread =
                new Thread(
                        null,
                        () -> {
                            try {
                                queries.set(new OSQueryBackend(Collections.emptyMap(), false).convertRule(rule));
                            } catch (Throwable t) {
                                failure.set(t);
                            }
                        },
                        "small-stack",
                        PRODUCTION_STACK / 4);
        thread.start();
        thread.join();

        assertNull(String.valueOf(failure.get()), failure.get());
        assertEquals(1, queries.get().size());
    }

    public void testStackOverflowWhileConvertingIsReportedAsAConditionError() throws Exception {
        // A backend that overflows stands in for a condition too deep for the stack: what reaches
        // the caller must be a condition error, never the StackOverflowError itself.
        QueryBackend overflowing =
                new OSQueryBackend(Collections.emptyMap(), false) {
                    @Override
                    public Object convertCondition(
                            ConditionType conditionType, boolean isConditionNot, boolean applyDeMorgans) {
                        throw new StackOverflowError();
                    }
                };
        SigmaRule rule = SigmaRule.fromYaml(rule("sel", ""), true);

        SigmaConditionError e =
                assertThrows(SigmaConditionError.class, () -> overflowing.convertRule(rule));
        assertTrue(e.getMessage(), e.getMessage().contains("too deeply nested"));
    }
}
