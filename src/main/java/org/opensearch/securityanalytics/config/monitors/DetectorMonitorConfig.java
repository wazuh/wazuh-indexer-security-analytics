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

    /**
     * Percolator index backing logtest rule evaluation for a log type.
     *
     * <p>Deliberately inside the {@code .opensearch-sap-*-detectors-queries*} pattern of {@link
     * #OPENSEARCH_SAP_RULE_INDEX_TEMPLATE}, so it inherits the very analysis settings a detector's
     * query index uses. That inheritance is what makes logtest and a deployed detector agree: same
     * compiler, same analyzers, same percolator — and it keeps agreeing when those settings change,
     * because there is no second copy to update.
     *
     * <p>Sharing the template pattern is safe in the other direction too: a detector's fan-out
     * searches the concrete query index names resolved from its monitor metadata, never a wildcard
     * ({@code TransportDocLevelMonitorFanOutAction#runPercolateQueryOnTransformedDocs}), so it can
     * never percolate against this index. Do not turn that into a wildcard.
     *
     * @param logType the integration's log type, already sanitized for use in an index name.
     * @return the logtest percolator index name.
     */
    public static String getLogtestRuleIndex(String logType) {
        return String.format(
                Locale.ROOT,
                ".opensearch-sap-%s-detectors-queries-logtest",
                logType.toLowerCase(Locale.ROOT));
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

    /**
     * Analysis overrides applied to the query index copy of every source field, keyed by the source
     * field's type. Both chains are defined in {@code mappings/detector-settings.json}: {@code text}
     * fields get the {@code rule_analyzer}, {@code keyword} fields the {@code rule_ws_normalizer},
     * and since WCS string fields are {@code keyword}, the normalizer is the chain that applies to
     * almost every real rule.
     *
     * <p>These overrides decide how a compiled Sigma query is compared against a document, so
     * whatever they contain applies identically to a deployed detector and to logtest, which copies
     * them onto its own percolator index.
     *
     * @return field properties to merge into the query index mapping, keyed by source field type.
     */
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
