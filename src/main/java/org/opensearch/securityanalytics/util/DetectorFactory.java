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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Factory class for creating {@link Detector} instances.
 *
 * <p>This utility class provides methods to create pre-configured Detector objects for Wazuh
 * integrations. Detectors are configured with sensible defaults including a 2-minute interval
 * schedule and automatic data stream naming based on category.
 */
public class DetectorFactory {

    /** Private constructor to prevent instantiation of utility class. */
    private DetectorFactory() {}

    /**
     * Creates a Detector object configured for the specified integration.
     *
     * <p>The detector is created with the following configuration: - Name: lowercase integration name
     * - Description: "Detector for {integration} integration" - Data stream:
     * "wazuh-events-v5-{category}" (lowercase) - Schedule: 2-minute interval - Enabled: true
     *
     * @param integration the integration name (e.g., "apache", "nginx")
     * @param category the log category used for data stream naming
     * @param detectorRules list of rule IDs to associate with the detector
     * @return a new {@link Detector} instance configured for the integration
     */
    public static Detector createDetector(
            String integration, String category, List<String> detectorRules) {

        List<DetectorRule> rules = new ArrayList<>();
        detectorRules.forEach(rule -> rules.add(new DetectorRule(rule)));

        Long version = 1L;
        String name = integration.toLowerCase(Locale.ROOT);
        String description = "Detector for " + integration + " integration";
        String dataStream = "wazuh-events-v5-" + category.toLowerCase(Locale.ROOT);
        IntervalSchedule schedule = new IntervalSchedule(2, ChronoUnit.MINUTES, null);
        DetectorInput detectorInput =
                new DetectorInput(description, List.of(dataStream), new ArrayList<>(), rules);
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
                false);
    }
}
