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

import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.test.OpenSearchTestCase;

public class RuleDetectorSyncTests extends OpenSearchTestCase {

    public void testDetectorsReferencingRuleQuery_prePackaged_targetsNestedPath() {
        QueryBuilder q =
                RuleDetectorSync.detectorsReferencingRuleQuery("pre_packaged_rules", "rule-123");

        assertTrue(q instanceof NestedQueryBuilder);
        NestedQueryBuilder nq = (NestedQueryBuilder) q;
        assertEquals("detector.inputs.detector_input.pre_packaged_rules", nq.path());
        assertTrue(
                nq.query().toString().contains("detector.inputs.detector_input.pre_packaged_rules.id"));
        assertTrue(nq.query().toString().contains("rule-123"));
    }

    public void testDetectorsReferencingRuleQuery_custom_targetsNestedPath() {
        QueryBuilder q = RuleDetectorSync.detectorsReferencingRuleQuery("custom_rules", "r1");

        assertTrue(q instanceof NestedQueryBuilder);
        assertEquals("detector.inputs.detector_input.custom_rules", ((NestedQueryBuilder) q).path());
    }
}
