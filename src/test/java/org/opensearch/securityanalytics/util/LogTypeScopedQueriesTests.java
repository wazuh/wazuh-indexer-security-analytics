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
package org.opensearch.securityanalytics.util;

import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Regression tests for issue #352. The guards that block deleting or renaming a log type looked its
 * rules and detectors up by name alone. A name is only unique within a space, so another space's
 * copy blocked the operation: both queries must be scoped to the space being operated on.
 */
public class LogTypeScopedQueriesTests extends OpenSearchTestCase {

    public void testRulesByLogTypeAndSpace_isScopedToTheSpace() {
        QueryBuilder query = RuleIndices.rulesByLogTypeAndSpace("windows", "draft");

        assertTrue(
                "expected a bool query but got " + query.getClass().getName(),
                query instanceof BoolQueryBuilder);
        BoolQueryBuilder bool = (BoolQueryBuilder) query;
        assertEquals(1, bool.filter().size());

        TermQueryBuilder spaceFilter = (TermQueryBuilder) bool.filter().get(0);
        assertEquals("rule.space", spaceFilter.fieldName());
        assertEquals("draft", spaceFilter.value());
    }

    public void testDetectorsByLogTypeAndSpace_isScopedToTheSource() {
        QueryBuilder query = DetectorIndices.detectorsByLogTypeAndSpace("windows", "draft");

        assertTrue(
                "expected a nested query but got " + query.getClass().getName(),
                query instanceof NestedQueryBuilder);
        BoolQueryBuilder bool = (BoolQueryBuilder) ((NestedQueryBuilder) query).query();
        assertEquals(1, bool.filter().size());

        TermQueryBuilder sourceFilter = (TermQueryBuilder) bool.filter().get(0);
        assertEquals("detector.source", sourceFilter.fieldName());
        assertEquals("draft", sourceFilter.value());
    }
}
