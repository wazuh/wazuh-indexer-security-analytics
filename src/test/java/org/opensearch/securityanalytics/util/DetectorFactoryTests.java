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

import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;

/** Unit tests for {@link DetectorFactory}. */
public class DetectorFactoryTests extends OpenSearchTestCase {

    public void testCreateDetector_withValidInputs() {
        String integration = "Apache";
        String category = "Network Activity";
        List<String> ruleIds = List.of("rule-1", "rule-2", "rule-3");

        // sources=null, interval=2, isEnabled=true
        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        Assert.assertNotNull(detector);
        Assert.assertEquals("apache", detector.getName());
        Assert.assertEquals("Apache", detector.getLogType());
        Assert.assertTrue(detector.getEnabled());
    }

    public void testCreateDetector_nameIsLowercase() {
        String integration = "NGINX";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        Assert.assertEquals("nginx", detector.getName());
    }

    public void testCreateDetector_dataStreamNaming() {
        String integration = "apache";
        String category = "Network Activity";
        List<String> ruleIds = List.of("rule-1");

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        DetectorInput input = detector.getInputs().get(0);
        String expectedDataStream = "wazuh-events-v5-network activity";
        Assert.assertTrue(input.getIndices().contains(expectedDataStream));
    }

    public void testCreateDetector_categoryIsLowercaseInDataStream() {
        String integration = "apache";
        String category = "SECURITY";
        List<String> ruleIds = List.of("rule-1");

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        DetectorInput input = detector.getInputs().get(0);
        String expectedDataStream = "wazuh-events-v5-security";
        Assert.assertTrue(input.getIndices().contains(expectedDataStream));
    }

    public void testCreateDetector_rulesAreConverted() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1", "rule-2");

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        DetectorInput input = detector.getInputs().get(0);
        List<DetectorRule> rules = input.getPrePackagedRules();
        Assert.assertEquals(2, rules.size());
        Assert.assertEquals("rule-1", rules.get(0).getId());
        Assert.assertEquals("rule-2", rules.get(1).getId());
    }

    public void testCreateDetector_emptyRulesList() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = Collections.emptyList();

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        DetectorInput input = detector.getInputs().get(0);
        Assert.assertTrue(input.getPrePackagedRules().isEmpty());
    }

    public void testCreateDetector_scheduleIsOneMinute() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        Assert.assertTrue(detector.getSchedule() instanceof IntervalSchedule);
        IntervalSchedule schedule = (IntervalSchedule) detector.getSchedule();
        Assert.assertEquals(2, schedule.getInterval());
        Assert.assertEquals(ChronoUnit.MINUTES, schedule.getUnit());
    }

    public void testCreateDetector_versionIsOne() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        // Verify the detector version is 1
        Assert.assertEquals(Long.valueOf(1L), detector.getVersion());
    }

    public void testCreateDetector_isEnabled() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        Assert.assertTrue(detector.getEnabled());
    }

    public void testCreateDetector_logTypeMatchesIntegration() {
        String integration = "CustomIntegration";
        String category = "Other";
        List<String> ruleIds = List.of("rule-1");

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        Assert.assertEquals("CustomIntegration", detector.getLogType());
    }

    public void testCreateDetector_hasOneInput() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        Assert.assertEquals(1, detector.getInputs().size());
    }

    public void testCreateDetector_inputDescriptionFormat() {
        String integration = "Apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector =
                DetectorFactory.createDetector(integration, category, ruleIds, null, 2, true);

        DetectorInput input = detector.getInputs().get(0);
        Assert.assertEquals("Detector for Apache integration", input.getDescription());
    }

    /**
     * Verifies that the detector is created with custom index sources instead of the default naming
     * convention.
     */
    public void testCreateDetector_withCustomSources() {
        List<String> customSources = List.of("index-1", "index-2");

        Detector detector =
                DetectorFactory.createDetector("apache", "security", List.of("r1"), customSources, 5, true);

        DetectorInput input = detector.getInputs().get(0);
        Assert.assertEquals(customSources, input.getIndices());
        Assert.assertEquals(2, input.getIndices().size());
    }

    /** Verifies that the detector schedule is correctly set using the custom interval provided. */
    public void testCreateDetector_withCustomInterval() {
        int customInterval = 10;

        Detector detector =
                DetectorFactory.createDetector(
                        "apache", "security", List.of("r1"), null, customInterval, true);

        IntervalSchedule schedule = (IntervalSchedule) detector.getSchedule();
        Assert.assertEquals(customInterval, schedule.getInterval());
    }

    /** Verifies that the detector's enabled/disabled state is correctly assigned during creation. */
    public void testCreateDetector_disabledState() {
        Detector detector =
                DetectorFactory.createDetector("apache", "security", List.of("r1"), null, 2, false);

        Assert.assertFalse("Detector should be disabled", detector.getEnabled());
    }
}
