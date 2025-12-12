package org.opensearch.securityanalytics.util;

import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

public class DetectorFactory {
    public static final String DEFAULT_RULE_INDEX = ".rules_development_0.0.1-rules_development_0.0.1_test-rule";
    /* Creates a Detector object with the given rules, log type, and index name */
    public static Detector createDetector(List<String> rulesIds, String logType, String indexName) {
        List<DetectorRule> detectorRules = new ArrayList<>();
        // Detector body/mapping
        String id = ""; // Empty ID for new detector
        Long version = 0L;
        String name = logType + "-detector";
        String description = "Detector for " + logType + " integration";
        String dataStream = "wazuh-events-v5*";
        IntervalSchedule schedule = new IntervalSchedule(1, ChronoUnit.MINUTES, null);
        // Add rules to detector input
        for (String ruleId : rulesIds) {
            detectorRules.add(new DetectorRule(ruleId));
        }
        DetectorInput detectorInput = new DetectorInput(description, List.of(dataStream), detectorRules, new ArrayList<>());
        // Generate Detector object with this template
        return new Detector(
                id,
                version,
                name,
                true,
                schedule,
                java.time.Instant.now(),
                java.time.Instant.now(),
                logType,
                null,
                List.of(detectorInput),
                new ArrayList<>(),
                new ArrayList<>(),
                DEFAULT_RULE_INDEX,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }
}
