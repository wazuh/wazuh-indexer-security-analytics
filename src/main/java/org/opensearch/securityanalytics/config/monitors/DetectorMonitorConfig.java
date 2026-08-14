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
package org.opensearch.securityanalytics.config.monitors;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

public class DetectorMonitorConfig {

    public static final String OPENSEARCH_SAP_RULE_INDEX_TEMPLATE =
            ".opensearch-sap-detectors-queries-index-template";

    public static String getRuleIndex(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-detectors-queries", logType);
    }

    public static String getRuleIndexOptimized(String logType) {
        return String.format(
                Locale.getDefault(),
                ".opensearch-sap-%s-detectors-queries-optimized-%s",
                logType,
                UUID.randomUUID());
    }

    public static String getAlertsIndex(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-alerts", logType);
    }

    public static String getAlertsHistoryIndex(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-alerts-history", logType);
    }

    public static String getAlertsHistoryIndexPattern(String logType) {
        return String.format(
                Locale.getDefault(), "<.opensearch-sap-%s-alerts-history-{now/d}-1>", logType);
    }

    public static String getAllAlertsIndicesPattern(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-alerts*", logType);
    }

    public static String getFindingsIndexPattern(String logType) {
        return String.format(Locale.getDefault(), "<.opensearch-sap-%s-findings-{now/d}-1>", logType);
    }

    public static String getFindingsIndex(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-findings", logType);
    }

    public static String getAllFindingsIndicesPattern(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-findings*", logType);
    }

    public static String getWazuhFindingsIndex(String logType) {
        return String.format(Locale.getDefault(), "wazuh-findings-v5-%s", logType);
    }

    public static String getWazuhFindingsIndexPattern(String logType) {
        return String.format(Locale.getDefault(), "<wazuh-findings-v5-%s-{now/d}-1>", logType);
    }

    public static String getAllWazuhFindingsIndicesPattern(String logType) {
        return String.format(Locale.getDefault(), "wazuh-findings-v5-%s-*", logType);
    }

    public static Map<String, Map<String, String>> getRuleIndexMappingsByType() {
        HashMap<String, String> properties = new HashMap<>();
        properties.put("analyzer", "rule_analyzer");
        HashMap<String, Map<String, String>> fieldMappingProperties = new HashMap<>();
        fieldMappingProperties.put("text", properties);
        // WCS string fields are mapped as `keyword`, not `text`. Attach a normalizer that
        // reuses the `rule_ws_filter` char_filter so the `_ws_` whitespace placeholder in compiled
        // Sigma queries is reversed to a space on keyword fields too; without this, any rule whose
        // match value contains a space (e.g. "Microsoft Intune") never matches and no finding fires.
        HashMap<String, String> keywordProperties = new HashMap<>();
        keywordProperties.put("normalizer", "rule_ws_normalizer");
        fieldMappingProperties.put("keyword", keywordProperties);
        return fieldMappingProperties;
    }

    public static class MonitorConfig {
        private final String alertsIndex;
        private final String alertsHistoryIndex;
        private final String alertsHistoryIndexPattern;
        private final String allAlertsIndicesPattern;
        private final String findingIndex;
        private final String findingsIndexPattern;
        private final String allFindingsIndicesPattern;
        private final String ruleIndex;

        private MonitorConfig(
                String alertsIndex,
                String alertsHistoryIndex,
                String alertsHistoryIndexPattern,
                String allAlertsIndicesPattern,
                String findingsIndex,
                String findingsIndexPattern,
                String allFindingsIndicesPattern,
                String ruleIndex) {
            this.alertsIndex = alertsIndex;
            this.alertsHistoryIndex = alertsHistoryIndex;
            this.alertsHistoryIndexPattern = alertsHistoryIndexPattern;
            this.allAlertsIndicesPattern = allAlertsIndicesPattern;
            this.findingIndex = findingsIndex;
            this.findingsIndexPattern = findingsIndexPattern;
            this.allFindingsIndicesPattern = allFindingsIndicesPattern;
            this.ruleIndex = ruleIndex;
        }

        public String getAlertsIndex() {
            return alertsIndex;
        }

        public String getAlertsHistoryIndex() {
            return alertsHistoryIndex;
        }

        public String getAlertsHistoryIndexPattern() {
            return alertsHistoryIndexPattern;
        }

        public String getAllAlertsIndicesPattern() {
            return allAlertsIndicesPattern;
        }

        public String getFindingsIndex() {
            return findingIndex;
        }

        public String getFindingsIndexPattern() {
            return findingsIndexPattern;
        }

        public String getAllFindingsIndicesPattern() {
            return allFindingsIndicesPattern;
        }

        public String getRuleIndex() {
            return ruleIndex;
        }
    }
}
