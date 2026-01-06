/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Unit tests for {@link DetectorFactory}.
 */
public class DetectorFactoryTests extends OpenSearchTestCase {

    public void testCreateDetector_withValidInputs() {
        String integration = "Apache";
        String category = "Network Activity";
        List<String> ruleIds = List.of("rule-1", "rule-2", "rule-3");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        Assert.assertNotNull(detector);
        Assert.assertEquals("apache", detector.getName());
        Assert.assertEquals("Apache", detector.getLogType());
        Assert.assertTrue(detector.getEnabled());
    }

    public void testCreateDetector_nameIsLowercase() {
        String integration = "NGINX";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        Assert.assertEquals("nginx", detector.getName());
    }

    public void testCreateDetector_dataStreamNaming() {
        String integration = "apache";
        String category = "Network Activity";
        List<String> ruleIds = List.of("rule-1");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        DetectorInput input = detector.getInputs().get(0);
        String expectedDataStream = "wazuh-events-v5-network activity";
        Assert.assertTrue(input.getIndices().contains(expectedDataStream));
    }

    public void testCreateDetector_categoryIsLowercaseInDataStream() {
        String integration = "apache";
        String category = "SECURITY";
        List<String> ruleIds = List.of("rule-1");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        DetectorInput input = detector.getInputs().get(0);
        String expectedDataStream = "wazuh-events-v5-security";
        Assert.assertTrue(input.getIndices().contains(expectedDataStream));
    }

    public void testCreateDetector_rulesAreConverted() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1", "rule-2");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        DetectorInput input = detector.getInputs().get(0);
        List<DetectorRule> rules = input.getCustomRules();
        Assert.assertEquals(2, rules.size());
        Assert.assertEquals("rule-1", rules.get(0).getId());
        Assert.assertEquals("rule-2", rules.get(1).getId());
    }

    public void testCreateDetector_emptyRulesList() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = Collections.emptyList();

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        DetectorInput input = detector.getInputs().get(0);
        Assert.assertTrue(input.getCustomRules().isEmpty());
    }

    public void testCreateDetector_scheduleIsOneMinute() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        Assert.assertTrue(detector.getSchedule() instanceof IntervalSchedule);
        IntervalSchedule schedule = (IntervalSchedule) detector.getSchedule();
        Assert.assertEquals(1, schedule.getInterval());
        Assert.assertEquals(ChronoUnit.MINUTES, schedule.getUnit());
    }

    public void testCreateDetector_versionIsOne() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        // Verify the detector version is 1
        Assert.assertEquals(Long.valueOf(1L), detector.getVersion());
    }

    public void testCreateDetector_isEnabled() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        Assert.assertTrue(detector.getEnabled());
    }

    public void testCreateDetector_logTypeMatchesIntegration() {
        String integration = "CustomIntegration";
        String category = "Other";
        List<String> ruleIds = List.of("rule-1");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        Assert.assertEquals("CustomIntegration", detector.getLogType());
    }

    public void testCreateDetector_hasOneInput() {
        String integration = "apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        Assert.assertEquals(1, detector.getInputs().size());
    }

    public void testCreateDetector_inputDescriptionFormat() {
        String integration = "Apache";
        String category = "Security";
        List<String> ruleIds = List.of("rule-1");

        Detector detector = DetectorFactory.createDetector(integration, category, ruleIds);

        DetectorInput input = detector.getInputs().get(0);
        Assert.assertEquals("Detector for Apache integration", input.getDescription());
    }
}
