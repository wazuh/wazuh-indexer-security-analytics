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

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.securityanalytics.rules.condition.ConditionAND;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionNOT;
import org.opensearch.securityanalytics.rules.condition.ConditionOR;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaDetectionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Map;

public class SigmaConditionTests extends OpenSearchTestCase {

    private static SigmaDetections detections(String... names)
            throws SigmaDetectionError,
                    SigmaModifierError,
                    SigmaValueError,
                    SigmaRegularExpressionError,
                    SigmaConditionError {
        Map<String, Object> detectionMap = new java.util.LinkedHashMap<>();
        for (String name : names) {
            detectionMap.put(name, Map.of("field", "value"));
        }
        detectionMap.put("condition", names[0]);
        return SigmaDetections.fromDict(detectionMap);
    }

    private static SigmaDetections detectionsWithCondition(String condition, String... names)
            throws SigmaDetectionError,
                    SigmaModifierError,
                    SigmaValueError,
                    SigmaRegularExpressionError,
                    SigmaConditionError {
        Map<String, Object> detectionMap = new java.util.LinkedHashMap<>();
        for (String name : names) {
            detectionMap.put(name, Map.of("field", "value"));
        }
        detectionMap.put("condition", condition);
        return SigmaDetections.fromDict(detectionMap);
    }

    private static ConditionItem parse(String condition, String... identifiers)
            throws SigmaDetectionError,
                    SigmaModifierError,
                    SigmaValueError,
                    SigmaRegularExpressionError,
                    SigmaConditionError {
        SigmaDetections dets = detectionsWithCondition(condition, identifiers);
        SigmaCondition sigmaCondition = new SigmaCondition(condition, dets);
        Pair<ConditionItem, ?> result = sigmaCondition.parsed();
        return result.getLeft();
    }

    // --- AND operator ---

    public void testAndLowercaseIsAccepted() throws Exception {
        ConditionItem item = parse("sel1 and sel2", "sel1", "sel2");
        assertNotNull(item);
        assertSame(ConditionAND.class, item.getClass());
    }

    public void testAndUppercaseIsAccepted() throws Exception {
        ConditionItem item = parse("sel1 AND sel2", "sel1", "sel2");
        assertNotNull(item);
        assertSame(ConditionAND.class, item.getClass());
    }

    public void testAndMixedCaseIsAccepted() throws Exception {
        ConditionItem item = parse("sel1 And sel2", "sel1", "sel2");
        assertNotNull(item);
        assertSame(ConditionAND.class, item.getClass());
    }

    // --- OR operator ---

    public void testOrLowercaseIsAccepted() throws Exception {
        ConditionItem item = parse("sel1 or sel2", "sel1", "sel2");
        assertNotNull(item);
        assertSame(ConditionOR.class, item.getClass());
    }

    public void testOrUppercaseIsAccepted() throws Exception {
        ConditionItem item = parse("sel1 OR sel2", "sel1", "sel2");
        assertNotNull(item);
        assertSame(ConditionOR.class, item.getClass());
    }

    public void testOrMixedCaseIsAccepted() throws Exception {
        ConditionItem item = parse("sel1 Or sel2", "sel1", "sel2");
        assertNotNull(item);
        assertSame(ConditionOR.class, item.getClass());
    }

    // --- NOT operator ---

    public void testNotLowercaseIsAccepted() throws Exception {
        ConditionItem item = parse("not sel1", "sel1");
        assertNotNull(item);
        assertSame(ConditionNOT.class, item.getClass());
    }

    public void testNotUppercaseIsAccepted() throws Exception {
        ConditionItem item = parse("NOT sel1", "sel1");
        assertNotNull(item);
        assertSame(ConditionNOT.class, item.getClass());
    }

    public void testNotMixedCaseIsAccepted() throws Exception {
        ConditionItem item = parse("Not sel1", "sel1");
        assertNotNull(item);
        assertSame(ConditionNOT.class, item.getClass());
    }

    // --- Chained operators ---

    public void testChainedUppercaseOperators() throws Exception {
        ConditionItem item = parse("sel1 AND sel2 OR NOT sel3", "sel1", "sel2", "sel3");
        assertNotNull(item);
    }

    public void testChainedMixedCaseOperators() throws Exception {
        ConditionItem item = parse("sel1 And sel2 Or Not sel3", "sel1", "sel2", "sel3");
        assertNotNull(item);
    }

    // --- Identifier names containing operator substrings are not mangled ---

    public void testIdentifierContainingAndSubstring() throws Exception {
        ConditionItem item = parse("android_sel AND norton_filter", "android_sel", "norton_filter");
        assertNotNull(item);
        assertSame(ConditionAND.class, item.getClass());
    }

    public void testIdentifierContainingOrSubstring() throws Exception {
        ConditionItem item = parse("selector OR oracle_filter", "selector", "oracle_filter");
        assertNotNull(item);
        assertSame(ConditionOR.class, item.getClass());
    }

    // --- Lowercase operators remain unaffected ---

    public void testLowercaseOperatorsUnchanged() throws Exception {
        ConditionItem andItem = parse("sel1 and sel2", "sel1", "sel2");
        ConditionItem andUpperItem = parse("sel1 AND sel2", "sel1", "sel2");
        assertSame(andItem.getClass(), andUpperItem.getClass());

        ConditionItem orItem = parse("sel1 or sel2", "sel1", "sel2");
        ConditionItem orUpperItem = parse("sel1 OR sel2", "sel1", "sel2");
        assertSame(orItem.getClass(), orUpperItem.getClass());

        ConditionItem notItem = parse("not sel1", "sel1");
        ConditionItem notUpperItem = parse("NOT sel1", "sel1");
        assertSame(notItem.getClass(), notUpperItem.getClass());
    }
}
