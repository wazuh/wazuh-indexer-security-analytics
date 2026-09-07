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
package org.opensearch.securityanalytics.model;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.randomDetectorInput;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorRule;

public class DetectorInputTests extends OpenSearchTestCase {

    public void testDetectorRuleAsTemplateArgs() {
        DetectorRule rule = randomDetectorRule();

        Map<String, Object> templateArgs = rule.asTemplateArg();

        Assert.assertEquals(
                "Template args 'id' field does not match:",
                templateArgs.get(DetectorRule.RULE_ID_FIELD),
                rule.getId());
    }

    public void testDetectorInputAsTemplateArgs() throws IOException {
        DetectorInput input = randomDetectorInput();

        Map<String, Object> templateArgs = input.asTemplateArg();

        Assert.assertEquals(
                "Template args 'description' field does not match:",
                templateArgs.get(DetectorInput.DESCRIPTION_FIELD),
                input.getDescription());

        Assert.assertEquals(
                "Template args 'indices' field does not match:",
                templateArgs.get(DetectorInput.INDICES_FIELD),
                input.getIndices());

        Assert.assertEquals(
                "Template args 'rules' field does not contain the expected number of rules:",
                ((List<?>) templateArgs.get(DetectorInput.CUSTOM_RULES_FIELD)).size(),
                input.getCustomRules().size());

        input
                .getCustomRules()
                .forEach(
                        detectorRule ->
                                Assert.assertTrue(
                                        ((List<?>) templateArgs.get(DetectorInput.CUSTOM_RULES_FIELD))
                                                .contains(detectorRule.asTemplateArg())));
    }
}
