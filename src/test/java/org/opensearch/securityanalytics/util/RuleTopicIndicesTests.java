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

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.test.OpenSearchTestCase;

import java.util.List;
import java.util.Map;

/**
 * Pins the analysis settings every detector query index inherits.
 *
 * <p>These assertions exist because nothing used to check them, and this analysis chain has been
 * the reason rules that looked fine in logtest produced no finding — once for values containing a
 * space (fixed, and guarded below), once for values differing only in case (still open, tracked
 * separately). A change here silently changes what every deployed detector matches, so it should
 * have to break a test first.
 *
 * <p>The logtest percolator index inherits these very settings by matching the same index template
 * pattern, so these assertions cover both evaluation paths at once.
 */
public class RuleTopicIndicesTests extends OpenSearchTestCase {

    private Settings settings() throws Exception {
        return Settings.builder()
                .loadFromSource(RuleTopicIndices.ruleTopicIndexSettings(), XContentType.JSON)
                .build();
    }

    public void testRuleAnalyzerIsNotTokenized() throws Exception {
        // A compiled Sigma query matches a whole field value, so the analyzer must not split it.
        assertEquals("keyword", settings().get("analysis.analyzer.rule_analyzer.tokenizer"));
    }

    public void testWhitespacePlaceholderIsStillReversed() throws Exception {
        // Guards the earlier fix: values containing a space are compiled with a _ws_ placeholder.
        assertEquals(
                List.of("rule_ws_filter"),
                settings().getAsList("analysis.analyzer.rule_analyzer.char_filter"));
        assertEquals(
                List.of("rule_ws_filter"),
                settings().getAsList("analysis.normalizer.rule_ws_normalizer.char_filter"));
        assertEquals("pattern_replace", settings().get("analysis.char_filter.rule_ws_filter.type"));
        assertEquals(" ", settings().get("analysis.char_filter.rule_ws_filter.replacement"));
    }

    public void testQueryIndexFieldOverridesUseTheAnalysisChains() {
        // WCS string fields are keyword, so the normalizer is the chain that applies to almost every
        // real rule; text fields get the analyzer. LogtestQueryIndex copies both onto its own fields.
        Map<String, Map<String, String>> overrides = DetectorMonitorConfig.getRuleIndexMappingsByType();

        assertEquals("rule_analyzer", overrides.get("text").get("analyzer"));
        assertEquals("rule_ws_normalizer", overrides.get("keyword").get("normalizer"));
    }
}
