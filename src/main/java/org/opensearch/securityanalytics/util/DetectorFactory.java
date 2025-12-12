package org.opensearch.securityanalytics.util;

import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

public class DetectorFactory {
    public static Detector createDetector(List<String> rulesIds, String logType, String indexName) {
        List<DetectorRule> detectorRules = new ArrayList<>();
        List<String> indices = List.of(indexName);
        // Def
//        Instant Instant = java.time.Instant.now().minusSeconds(3600);
        IntervalSchedule schedule = new IntervalSchedule(1, ChronoUnit.MINUTES, null);
        String description = "Detector for " + logType + " integration";

        for (String ruleId : rulesIds) {
            detectorRules.add(new DetectorRule(ruleId));
        }

        List<DetectorInput> inputs = List.of(new DetectorInput(description, indices, new ArrayList<>(), detectorRules));

        return new Detector(
                "",
                0L,
                "Test detector",
                true,
                schedule,
                java.time.Instant.now(),
                java.time.Instant.now(),
                logType,
                null,
                inputs,
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
