package org.opensearch.securityanalytics.util;

import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

public class DetectorFactory {
    /* Creates a Detector object with the given rules, log type, and index name */
    public static Detector createDetector(List<String> rulesIds, String logType, String indexName) {
        List<DetectorRule> detectorRules = new ArrayList<>();
        // Detector body/mapping
        String id = ""; // Empty ID for new detector
        Long version = 0L; // Initial version
        String name = logType + "-detector"; // e.g., "cisco-ios-detector"
        String description = "Detector for " + logType + " integration";
        List<String> indices = List.of(indexName);
        IntervalSchedule schedule = new IntervalSchedule(1, ChronoUnit.MINUTES, null);
        // Add rules to detector input
        for (String ruleId : rulesIds) {
            detectorRules.add(new DetectorRule(ruleId));
        }
        DetectorInput detectorInput = new DetectorInput(description, indices, new ArrayList<>(), detectorRules);

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
                null,
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
