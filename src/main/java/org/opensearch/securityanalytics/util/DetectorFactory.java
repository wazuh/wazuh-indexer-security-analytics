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
    public static Detector createDetector(String integration, List<String> detectorRules) {

        List<DetectorRule> rules = new ArrayList<>();
        detectorRules.forEach(rule -> rules.add(new DetectorRule(rule)));

        Long version = 1L;
        String name = integration + "-detector";
        String description = "Detector for " + integration + " integration";
        String dataStream = "wazuh-events-v5-other";
        IntervalSchedule schedule = new IntervalSchedule(1, ChronoUnit.MINUTES, null);
        DetectorInput detectorInput = new DetectorInput(description, List.of(dataStream), rules, new ArrayList<>());
        // Generate Detector object with this template
        return new Detector(
                "Detector for " + integration,
                version,
                name,
                true,
                schedule,
                java.time.Instant.now(),
                java.time.Instant.now(),
                integration,
                null,
                List.of(detectorInput),
                new ArrayList<>(),
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                false
        );
    }
}
