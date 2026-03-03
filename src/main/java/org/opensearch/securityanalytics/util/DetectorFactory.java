package org.opensearch.securityanalytics.util;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;

/**
 * Factory class for creating {@link Detector} instances.
 *
 * This utility class provides methods to create pre-configured Detector objects
 * for Wazuh integrations. Detectors are configured with sensible defaults including
 * a 1-minute interval schedule and automatic data stream naming based on category.
 */
public class DetectorFactory {

    /** Private constructor to prevent instantiation of utility class. */
    private DetectorFactory() {}

    /**
     * Creates a Detector object configured for the specified integration.
     *
     * The detector is created with the following configuration:
     * - Name: lowercase integration name
     * - Description: "Detector for {integration} integration"
     * - Data stream: "wazuh-events-v5-{category}" (lowercase)
     * - Schedule: 1-minute interval
     * - Enabled: true
     *
     * @param integration   the integration name (e.g., "apache", "nginx")
     * @param category      the log category used for data stream naming
     * @param detectorRules list of rule IDs to associate with the detector
     * @return a new {@link Detector} instance configured for the integration
     */
    public static Detector createDetector(String integration, String category, List<String> detectorRules) {

        List<DetectorRule> rules = new ArrayList<>();
        detectorRules.forEach(rule -> rules.add(new DetectorRule(rule)));

        Long version = 1L;
        String name = integration.toLowerCase(Locale.ROOT);
        String description = "Detector for " + integration + " integration";
        String dataStream = "wazuh-events-v5-" + category.toLowerCase(Locale.ROOT);
        IntervalSchedule schedule = new IntervalSchedule(1, ChronoUnit.MINUTES, null);
        DetectorInput detectorInput = new DetectorInput(description, List.of(dataStream), new ArrayList<>(), rules);
        // Generate Detector object with this template
        return new Detector(
            "Detector for " + integration,
            version,
            name,
            true,
            schedule,
            Instant.now(),
            Instant.now(),
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
