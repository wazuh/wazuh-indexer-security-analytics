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
package org.opensearch.securityanalytics.settings;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;

/** Unit tests for the Wazuh resource limit settings of the Security Analytics plugin. */
public class SecurityAnalyticsSettingsTests extends OpenSearchTestCase {

    /** The resource limit settings fall back to their documented defaults. */
    public void testResourceLimitDefaults() {
        assertEquals(10, (int) SecurityAnalyticsSettings.MAX_DETECTORS.get(Settings.EMPTY));
        assertEquals(50, (int) SecurityAnalyticsSettings.MAX_RULES_PER_DETECTOR.get(Settings.EMPTY));
    }

    /** The resource limit settings have no upper bound. */
    public void testResourceLimitsHaveNoUpperBound() {
        Settings settings =
                Settings.builder()
                        .put("plugins.security_analytics.max_detectors", 100_000)
                        .put("plugins.security_analytics.max_rules_per_detector", 100_000)
                        .build();

        assertEquals(100_000, (int) SecurityAnalyticsSettings.MAX_DETECTORS.get(settings));
        assertEquals(100_000, (int) SecurityAnalyticsSettings.MAX_RULES_PER_DETECTOR.get(settings));
    }

    /** The resource limit settings accept Integer.MAX_VALUE. */
    public void testResourceLimitsAcceptIntegerMaxValue() {
        Settings settings =
                Settings.builder()
                        .put("plugins.security_analytics.max_detectors", Integer.MAX_VALUE)
                        .put("plugins.security_analytics.max_rules_per_detector", Integer.MAX_VALUE)
                        .build();

        assertEquals(Integer.MAX_VALUE, (int) SecurityAnalyticsSettings.MAX_DETECTORS.get(settings));
        assertEquals(
                Integer.MAX_VALUE, (int) SecurityAnalyticsSettings.MAX_RULES_PER_DETECTOR.get(settings));
    }

    /** Zero is still a valid limit, blocking creation of the resource. */
    public void testResourceLimitsAcceptZero() {
        Settings settings =
                Settings.builder()
                        .put("plugins.security_analytics.max_detectors", 0)
                        .put("plugins.security_analytics.max_rules_per_detector", 0)
                        .build();

        assertEquals(0, (int) SecurityAnalyticsSettings.MAX_DETECTORS.get(settings));
        assertEquals(0, (int) SecurityAnalyticsSettings.MAX_RULES_PER_DETECTOR.get(settings));
    }

    /** The resource limit settings keep their zero floor. */
    public void testResourceLimitsRejectNegativeValues() {
        Settings detectors =
                Settings.builder().put("plugins.security_analytics.max_detectors", -1).build();
        Settings rulesPerDetector =
                Settings.builder().put("plugins.security_analytics.max_rules_per_detector", -1).build();

        expectThrows(
                IllegalArgumentException.class,
                () -> SecurityAnalyticsSettings.MAX_DETECTORS.get(detectors));
        expectThrows(
                IllegalArgumentException.class,
                () -> SecurityAnalyticsSettings.MAX_RULES_PER_DETECTOR.get(rulesPerDetector));
    }
}
