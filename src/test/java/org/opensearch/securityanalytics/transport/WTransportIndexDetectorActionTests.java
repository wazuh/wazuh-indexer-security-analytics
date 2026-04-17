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

import org.opensearch.test.OpenSearchTestCase;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WTransportIndexDetectorActionTests extends OpenSearchTestCase {

    public void testClassifyRuleWorld_nullSpace_returnsStandard() {
        assertEquals("Standard", WTransportIndexDetectorAction.classifyRuleWorld(null));
    }

    public void testClassifyRuleWorld_sigmaSpace_returnsStandard() {
        assertEquals("Standard", WTransportIndexDetectorAction.classifyRuleWorld("Sigma"));
    }

    public void testClassifyRuleWorld_sigmaCaseInsensitive_returnsStandard() {
        assertEquals("Standard", WTransportIndexDetectorAction.classifyRuleWorld("sigma"));
        assertEquals("Standard", WTransportIndexDetectorAction.classifyRuleWorld("SIGMA"));
    }

    public void testClassifyRuleWorld_draftSpace_returnsUser() {
        assertEquals("User", WTransportIndexDetectorAction.classifyRuleWorld("Draft"));
    }

    public void testClassifyRuleWorld_testSpace_returnsUser() {
        assertEquals("User", WTransportIndexDetectorAction.classifyRuleWorld("Test"));
    }

    public void testClassifyRuleWorld_customSpace_returnsUser() {
        assertEquals("User", WTransportIndexDetectorAction.classifyRuleWorld("Custom"));
    }

    public void testClassifyRuleWorld_unknownSpace_returnsUser() {
        assertEquals("User", WTransportIndexDetectorAction.classifyRuleWorld("SomeOtherSpace"));
    }

    public void testClassifyRuleWorld_emptyString_returnsUser() {
        assertEquals("User", WTransportIndexDetectorAction.classifyRuleWorld(""));
    }

    public void testValidateRuleWorlds_allStandard_returnsNull() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("rule-1", "Standard");
        worldMap.put("rule-2", "Standard");

        assertNull(
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("rule-1", "rule-2"), "test-log-type"));
    }

    public void testValidateRuleWorlds_allUser_returnsNull() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("rule-1", "User");
        worldMap.put("rule-2", "User");

        assertNull(
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("rule-1", "rule-2"), "test-log-type"));
    }

    public void testValidateRuleWorlds_mixedWorlds_returnsError() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("rule-standard", "Standard");
        worldMap.put("rule-user", "User");

        String error =
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("rule-standard", "rule-user"), "my-integration");

        assertNotNull(error);
        assertTrue(error.contains("my-integration"));
        assertTrue(error.contains("standard or custom"));
    }

    public void testValidateRuleWorlds_singleRule_standard_returnsNull() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("only-rule", "Standard");

        assertNull(
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("only-rule"), "test-log-type"));
    }

    public void testValidateRuleWorlds_singleRule_user_returnsNull() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("only-rule", "User");

        assertNull(
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("only-rule"), "test-log-type"));
    }

    public void testValidateRuleWorlds_emptyRuleList_returnsNull() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("rule-1", "Standard");

        assertNull(
                WTransportIndexDetectorAction.validateRuleWorlds(worldMap, List.of(), "test-log-type"));
    }

    public void testValidateRuleWorlds_ruleNotInMap_ignored() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("rule-1", "Standard");

        assertNull(
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("rule-1", "rule-2"), "test-log-type"));
    }

    public void testValidateRuleWorlds_multipleStandardWithMissingRules_returnsNull() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("rule-a", "Standard");
        worldMap.put("rule-b", "Standard");

        assertNull(
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("rule-a", "rule-b", "rule-missing"), "test-log-type"));
    }

    public void testValidateRuleWorlds_mixedWithMissing_returnsError() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("rule-std", "Standard");
        worldMap.put("rule-usr", "User");

        String error =
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("rule-std", "rule-usr", "rule-missing"), "mixed-int");

        assertNotNull(error);
        assertTrue(error.contains("mixed-int"));
    }

    public void testValidateRuleWorlds_noRulesFoundInMap_returnsNull() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("other-rule", "Standard");

        assertNull(
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("missing-1", "missing-2"), "test-log-type"));
    }

    public void testClassifyAndValidate_sigmaAndNull_bothStandard() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("rule-sigma", WTransportIndexDetectorAction.classifyRuleWorld("Sigma"));
        worldMap.put("rule-null", WTransportIndexDetectorAction.classifyRuleWorld(null));

        assertNull(
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("rule-sigma", "rule-null"), "test"));
    }

    public void testClassifyAndValidate_draftTestCustom_allUser() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("r1", WTransportIndexDetectorAction.classifyRuleWorld("Draft"));
        worldMap.put("r2", WTransportIndexDetectorAction.classifyRuleWorld("Test"));
        worldMap.put("r3", WTransportIndexDetectorAction.classifyRuleWorld("Custom"));

        assertNull(
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("r1", "r2", "r3"), "test"));
    }

    public void testClassifyAndValidate_sigmaAndCustom_rejected() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("std", WTransportIndexDetectorAction.classifyRuleWorld("Sigma"));
        worldMap.put("cust", WTransportIndexDetectorAction.classifyRuleWorld("Custom"));

        String error =
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("std", "cust"), "wazuh-rootcheck");

        assertNotNull(error);
        assertTrue(error.contains("wazuh-rootcheck"));
    }

    public void testClassifyAndValidate_nullAndDraft_rejected() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("std", WTransportIndexDetectorAction.classifyRuleWorld(null));
        worldMap.put("draft", WTransportIndexDetectorAction.classifyRuleWorld("Draft"));

        String error =
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("std", "draft"), "my-type");

        assertNotNull(error);
    }

    public void testClassifyAndValidate_emptyStringAndSigma_rejected() {
        Map<String, String> worldMap = new HashMap<>();
        worldMap.put("rule-empty", WTransportIndexDetectorAction.classifyRuleWorld(""));
        worldMap.put("rule-sigma", WTransportIndexDetectorAction.classifyRuleWorld("Sigma"));

        String error =
                WTransportIndexDetectorAction.validateRuleWorlds(
                        worldMap, List.of("rule-empty", "rule-sigma"), "mixed-edge-case");

        assertNotNull(error);
        assertTrue(error.contains("mixed-edge-case"));
    }
}
