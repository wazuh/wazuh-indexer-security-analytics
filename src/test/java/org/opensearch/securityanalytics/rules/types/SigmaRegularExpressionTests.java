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
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.test.OpenSearchTestCase;

public class SigmaRegularExpressionTests extends OpenSearchTestCase {

    public void testPatternAtTheLimitsIsAccepted() throws Exception {
        int groups = SigmaRegularExpression.MAX_REGEX_PARENTHESES;
        String nested = "(".repeat(groups) + "a" + ")".repeat(groups);
        String pattern = nested + "b".repeat(SigmaRegularExpression.MAX_REGEX_LENGTH - nested.length());
        assertEquals(SigmaRegularExpression.MAX_REGEX_LENGTH, pattern.length());

        assertEquals(pattern, new SigmaRegularExpression(pattern).getRegexp());
    }

    public void testPatternLongerThanTheLimitIsRefused() {
        String pattern = "a".repeat(SigmaRegularExpression.MAX_REGEX_LENGTH + 1);
        SigmaRegularExpressionError e =
                assertThrows(SigmaRegularExpressionError.class, () -> new SigmaRegularExpression(pattern));
        assertTrue(
                e.getMessage(),
                e.getMessage()
                        .contains(
                                (SigmaRegularExpression.MAX_REGEX_LENGTH + 1)
                                        + " characters long, more than the "
                                        + SigmaRegularExpression.MAX_REGEX_LENGTH));
    }

    public void testNestedGroupsPastTheLimitAreRefused() {
        int groups = SigmaRegularExpression.MAX_REGEX_PARENTHESES + 1;
        String pattern = "(".repeat(groups) + "a" + ")".repeat(groups);
        SigmaRegularExpressionError e =
                assertThrows(SigmaRegularExpressionError.class, () -> new SigmaRegularExpression(pattern));
        assertTrue(
                e.getMessage(),
                e.getMessage()
                        .contains(
                                groups
                                        + " opening parentheses, more than the "
                                        + SigmaRegularExpression.MAX_REGEX_PARENTHESES));
    }

    public void testSequentialGroupsCountTowardsTheLimit() {
        // Sequential groups nest no deeper than one, but the count is what is bounded: it caps the
        // depth whatever reading the pattern is given downstream.
        String pattern = "(a)".repeat(SigmaRegularExpression.MAX_REGEX_PARENTHESES + 1);
        assertThrows(SigmaRegularExpressionError.class, () -> new SigmaRegularExpression(pattern));
    }

    public void testEscapedParenthesesCountTowardsTheLimit() {
        // Java reads these as literal parentheses, but the query backend doubles backslashes on
        // the way to Lucene, which would then read every one of them as a group.
        int groups = SigmaRegularExpression.MAX_REGEX_PARENTHESES + 1;
        String pattern = "\\(".repeat(groups) + "a" + "\\)".repeat(groups);
        assertThrows(SigmaRegularExpressionError.class, () -> new SigmaRegularExpression(pattern));
    }

    public void testInvalidPatternIsStillRefused() {
        SigmaRegularExpressionError e =
                assertThrows(SigmaRegularExpressionError.class, () -> new SigmaRegularExpression("(a"));
        assertTrue(e.getMessage(), e.getMessage().contains("is invalid"));
    }
}
