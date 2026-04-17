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

import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.List;

import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;

public class TransportIndexDetectorActionTests extends OpenSearchTestCase {

    public void testValidateSingleRuleSpace_onlyPrePackaged_returnsNull() {
        List<DetectorRule> prePackaged =
                List.of(new DetectorRule("rule-1"), new DetectorRule("rule-2"));
        DetectorInput input =
                new DetectorInput("test", List.of("index-1"), Collections.emptyList(), prePackaged);
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(TransportIndexDetectorAction.validateSingleRuleSpace(detector));
    }

    public void testValidateSingleRuleSpace_onlyCustom_returnsNull() {
        List<DetectorRule> custom = List.of(new DetectorRule("rule-1"), new DetectorRule("rule-2"));
        DetectorInput input =
                new DetectorInput("test", List.of("index-1"), custom, Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(TransportIndexDetectorAction.validateSingleRuleSpace(detector));
    }

    public void testValidateSingleRuleSpace_bothTypes_returnsError() {
        List<DetectorRule> prePackaged = List.of(new DetectorRule("std-rule-1"));
        List<DetectorRule> custom = List.of(new DetectorRule("custom-rule-1"));
        DetectorInput input = new DetectorInput("test", List.of("index-1"), custom, prePackaged);
        Detector detector = randomDetectorWithInputs(List.of(input));

        String error = TransportIndexDetectorAction.validateSingleRuleSpace(detector);
        assertNotNull(error);
        assertTrue(error.contains("both prepackaged and custom rules"));
    }

    public void testValidateSingleRuleSpace_emptyRules_returnsNull() {
        DetectorInput input =
                new DetectorInput(
                        "test", List.of("index-1"), Collections.emptyList(), Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(TransportIndexDetectorAction.validateSingleRuleSpace(detector));
    }

    public void testValidateSingleRuleSpace_nullRuleLists_returnsNull() {
        DetectorInput input = new DetectorInput("test", List.of("index-1"), null, null);
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(TransportIndexDetectorAction.validateSingleRuleSpace(detector));
    }
}
