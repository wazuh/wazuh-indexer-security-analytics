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
import org.opensearch.index.query.MatchPhraseQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.test.OpenSearchTestCase;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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

    public void testDetectorsReferencingAnyRuleQuery_matchesEachIdAsAPhraseInBothLists() {
        List<String> ruleIds =
                List.of("26a8d32e-0838-5589-948c-501b5a301cf5", "a1776000-0000-4000-8000-000000000001");

        QueryBuilder q = RuleDetectorSync.detectorsReferencingAnyRuleQuery(ruleIds);

        assertTrue(q instanceof BoolQueryBuilder);
        List<QueryBuilder> lists = ((BoolQueryBuilder) q).should();
        assertEquals(
                Set.of(
                        "detector.inputs.detector_input.custom_rules",
                        "detector.inputs.detector_input.pre_packaged_rules"),
                lists.stream().map(n -> ((NestedQueryBuilder) n).path()).collect(Collectors.toSet()));
        for (QueryBuilder list : lists) {
            NestedQueryBuilder nested = (NestedQueryBuilder) list;
            List<QueryBuilder> ids = ((BoolQueryBuilder) nested.query()).should();
            assertEquals(ruleIds.size(), ids.size());
            for (QueryBuilder id : ids) {
                MatchPhraseQueryBuilder phrase = (MatchPhraseQueryBuilder) id;
                assertEquals(nested.path() + ".id", phrase.fieldName());
                assertTrue(ruleIds.contains((String) phrase.value()));
            }
        }
    }
}
