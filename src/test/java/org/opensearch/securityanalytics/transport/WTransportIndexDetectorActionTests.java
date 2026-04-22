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

import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.transport.WTransportIndexDetectorAction.RuleClassificationResult;
import org.opensearch.securityanalytics.transport.WTransportIndexDetectorAction.RuleHit;
import org.opensearch.test.OpenSearchTestCase;

import java.util.ArrayList;
import java.util.List;

public class WTransportIndexDetectorActionTests extends OpenSearchTestCase {

    // -----------------------------------------------------------------------
    // classifyRuleHits tests
    // -----------------------------------------------------------------------

    public void testClassifyRuleHits_allPrePackaged() {
        List<RuleHit> hits =
                List.of(
                        new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "rule-1", "Sigma"),
                        new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "rule-2", "Sigma"));

        RuleClassificationResult result = WTransportIndexDetectorAction.classifyRuleHits(hits);

        assertEquals(2, result.prePackagedRuleIds.size());
        assertTrue(result.prePackagedRuleIds.contains("rule-1"));
        assertTrue(result.prePackagedRuleIds.contains("rule-2"));
        assertTrue(result.customRuleIds.isEmpty());
        assertTrue(result.invalidCustomRules.isEmpty());
        assertEquals(2, result.foundRuleIds.size());
    }

    public void testClassifyRuleHits_allCustomWithCustomSpace() {
        List<RuleHit> hits =
                List.of(
                        new RuleHit(Rule.CUSTOM_RULES_INDEX, "rule-1", "Custom"),
                        new RuleHit(Rule.CUSTOM_RULES_INDEX, "rule-2", "custom"));

        RuleClassificationResult result = WTransportIndexDetectorAction.classifyRuleHits(hits);

        assertTrue(result.prePackagedRuleIds.isEmpty());
        assertEquals(2, result.customRuleIds.size());
        assertTrue(result.invalidCustomRules.isEmpty());
    }

    public void testClassifyRuleHits_customRuleWithDraftSpace_invalid() {
        List<RuleHit> hits = List.of(new RuleHit(Rule.CUSTOM_RULES_INDEX, "rule-1", "Draft"));

        RuleClassificationResult result = WTransportIndexDetectorAction.classifyRuleHits(hits);

        assertTrue(result.prePackagedRuleIds.isEmpty());
        assertTrue(result.customRuleIds.isEmpty());
        assertEquals(1, result.invalidCustomRules.size());
        assertEquals("rule-1", result.invalidCustomRules.get(0));
    }

    public void testClassifyRuleHits_customRuleWithTestSpace_invalid() {
        List<RuleHit> hits = List.of(new RuleHit(Rule.CUSTOM_RULES_INDEX, "rule-1", "Test"));

        RuleClassificationResult result = WTransportIndexDetectorAction.classifyRuleHits(hits);

        assertTrue(result.customRuleIds.isEmpty());
        assertEquals(1, result.invalidCustomRules.size());
    }

    public void testClassifyRuleHits_customRuleWithNullSpace_invalid() {
        List<RuleHit> hits = List.of(new RuleHit(Rule.CUSTOM_RULES_INDEX, "rule-1", null));

        RuleClassificationResult result = WTransportIndexDetectorAction.classifyRuleHits(hits);

        assertTrue(result.customRuleIds.isEmpty());
        assertEquals(1, result.invalidCustomRules.size());
    }

    public void testClassifyRuleHits_mixedPrePackagedAndCustom() {
        List<RuleHit> hits =
                List.of(
                        new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "rule-std", "Sigma"),
                        new RuleHit(Rule.CUSTOM_RULES_INDEX, "rule-cust", "Custom"));

        RuleClassificationResult result = WTransportIndexDetectorAction.classifyRuleHits(hits);

        assertEquals(1, result.prePackagedRuleIds.size());
        assertEquals(1, result.customRuleIds.size());
        assertTrue(result.invalidCustomRules.isEmpty());
        assertEquals(2, result.foundRuleIds.size());
    }

    public void testClassifyRuleHits_emptyHits() {
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(new ArrayList<>());

        assertTrue(result.prePackagedRuleIds.isEmpty());
        assertTrue(result.customRuleIds.isEmpty());
        assertTrue(result.invalidCustomRules.isEmpty());
        assertTrue(result.foundRuleIds.isEmpty());
    }

    public void testClassifyRuleHits_prePackagedWithAnySpace_accepted() {
        // Pre-packaged rules are accepted regardless of their space value
        List<RuleHit> hits =
                List.of(
                        new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "rule-1", "Sigma"),
                        new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "rule-2", null),
                        new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "rule-3", "SomeOther"));

        RuleClassificationResult result = WTransportIndexDetectorAction.classifyRuleHits(hits);

        assertEquals(3, result.prePackagedRuleIds.size());
        assertTrue(result.customRuleIds.isEmpty());
        assertTrue(result.invalidCustomRules.isEmpty());
    }

    public void testClassifyRuleHits_customRuleWithEmptySpace_invalid() {
        List<RuleHit> hits = List.of(new RuleHit(Rule.CUSTOM_RULES_INDEX, "rule-1", ""));

        RuleClassificationResult result = WTransportIndexDetectorAction.classifyRuleHits(hits);

        assertTrue(result.customRuleIds.isEmpty());
        assertEquals(1, result.invalidCustomRules.size());
    }

    // -----------------------------------------------------------------------
    // validateClassificationResult tests
    // -----------------------------------------------------------------------

    public void testValidate_allPrePackaged_returnsNull() {
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(
                        List.of(
                                new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "r1", "Sigma"),
                                new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "r2", "Sigma")));

        assertNull(WTransportIndexDetectorAction.validateClassificationResult(result, "test-type"));
    }

    public void testValidate_allCustom_returnsNull() {
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(
                        List.of(
                                new RuleHit(Rule.CUSTOM_RULES_INDEX, "r1", "Custom"),
                                new RuleHit(Rule.CUSTOM_RULES_INDEX, "r2", "Custom")));

        assertNull(WTransportIndexDetectorAction.validateClassificationResult(result, "test-type"));
    }

    public void testValidate_mixed_returnsError() {
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(
                        List.of(
                                new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "r-std", "Sigma"),
                                new RuleHit(Rule.CUSTOM_RULES_INDEX, "r-cust", "Custom")));

        String error =
                WTransportIndexDetectorAction.validateClassificationResult(result, "my-integration");

        assertNotNull(error);
        assertTrue(error.contains("my-integration"));
        assertTrue(error.contains("pre-packaged or all custom"));
    }

    public void testValidate_invalidCustomSpace_returnsError() {
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(
                        List.of(new RuleHit(Rule.CUSTOM_RULES_INDEX, "r-draft", "Draft")));

        String error = WTransportIndexDetectorAction.validateClassificationResult(result, "my-type");

        assertNotNull(error);
        assertTrue(error.contains("my-type"));
        assertTrue(error.contains("not in \"Custom\" space"));
        assertTrue(error.contains("r-draft"));
    }

    public void testValidate_invalidCustomSpace_takePrecedenceOverMixedCheck() {
        // If there are invalid custom rules AND pre-packaged rules, the invalid space
        // error should be reported (it's checked first)
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(
                        List.of(
                                new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "r-std", "Sigma"),
                                new RuleHit(Rule.CUSTOM_RULES_INDEX, "r-draft", "Draft")));

        String error = WTransportIndexDetectorAction.validateClassificationResult(result, "test");

        assertNotNull(error);
        assertTrue(error.contains("not in \"Custom\" space"));
    }

    public void testValidate_empty_returnsNull() {
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(new ArrayList<>());

        assertNull(WTransportIndexDetectorAction.validateClassificationResult(result, "test"));
    }

    public void testValidate_singlePrePackaged_returnsNull() {
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(
                        List.of(new RuleHit(Rule.PRE_PACKAGED_RULES_INDEX, "only-rule", "Sigma")));

        assertNull(WTransportIndexDetectorAction.validateClassificationResult(result, "test"));
    }

    public void testValidate_singleCustom_returnsNull() {
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(
                        List.of(new RuleHit(Rule.CUSTOM_RULES_INDEX, "only-rule", "Custom")));

        assertNull(WTransportIndexDetectorAction.validateClassificationResult(result, "test"));
    }

    public void testValidate_multipleInvalidCustomSpaces_allReported() {
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(
                        List.of(
                                new RuleHit(Rule.CUSTOM_RULES_INDEX, "r-draft", "Draft"),
                                new RuleHit(Rule.CUSTOM_RULES_INDEX, "r-test", "Test")));

        String error = WTransportIndexDetectorAction.validateClassificationResult(result, "my-type");

        assertNotNull(error);
        assertTrue(error.contains("r-draft"));
        assertTrue(error.contains("r-test"));
    }

    public void testValidate_customCaseInsensitive_accepted() {
        RuleClassificationResult result =
                WTransportIndexDetectorAction.classifyRuleHits(
                        List.of(
                                new RuleHit(Rule.CUSTOM_RULES_INDEX, "r1", "CUSTOM"),
                                new RuleHit(Rule.CUSTOM_RULES_INDEX, "r2", "custom")));

        assertNull(WTransportIndexDetectorAction.validateClassificationResult(result, "test"));
    }
}
