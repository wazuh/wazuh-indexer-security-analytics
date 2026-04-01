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
package org.opensearch.securityanalytics.rules.engine;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class EventMatcherTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final EventMatcher matcher = new EventMatcher();

    // ---- Helper to build a minimal Sigma rule YAML ----

    private static String ruleYaml(String title, String detection) {
        return String.join(
                "\n",
                "title: " + title,
                "status: test",
                "logsource:",
                "    category: test",
                "detection:",
                detection,
                "    condition: selection",
                "level: high");
    }

    private static SigmaRule parseRule(String yaml) throws Exception {
        return SigmaRule.fromYaml(yaml, true);
    }

    // ---- Basic matching ----

    public void testSimpleFieldMatch() throws Exception {
        String yaml = ruleYaml("Simple Match", "    selection:\n        process.name: cmd.exe");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"process\": {\"name\": \"cmd.exe\"}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(1, parsed.get("rules_evaluated"));
        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    public void testSimpleFieldNoMatch() throws Exception {
        String yaml = ruleYaml("No Match", "    selection:\n        process.name: cmd.exe");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"process\": {\"name\": \"notepad.exe\"}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(1, parsed.get("rules_evaluated"));
        Assert.assertEquals(0, parsed.get("rules_matched"));
    }

    // ---- Case-insensitive matching ----

    public void testCaseInsensitiveMatch() throws Exception {
        String yaml = ruleYaml("Case Insensitive", "    selection:\n        process.name: CMD.EXE");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"process\": {\"name\": \"cmd.exe\"}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    // ---- Wildcard matching ----

    public void testWildcardMultiMatch() throws Exception {
        String yaml = ruleYaml("Wildcard Multi", "    selection:\n        process.name: cmd*");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"process\": {\"name\": \"cmd.exe\"}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    public void testWildcardSingleCharMatch() throws Exception {
        String yaml = ruleYaml("Wildcard Single", "    selection:\n        process.name: cm?.exe");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"process\": {\"name\": \"cmd.exe\"}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    public void testWildcardNoMatch() throws Exception {
        String yaml =
                ruleYaml("Wildcard No Match", "    selection:\n        process.name: powershell*");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"process\": {\"name\": \"cmd.exe\"}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals(0, parsed.get("rules_matched"));
    }

    // ---- Numeric matching ----

    public void testNumericMatch() throws Exception {
        String yaml = ruleYaml("Numeric Match", "    selection:\n        event.code: 4688");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"event\": {\"code\": 4688}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    public void testNumericNoMatch() throws Exception {
        String yaml = ruleYaml("Numeric No Match", "    selection:\n        event.code: 4688");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"event\": {\"code\": 1234}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals(0, parsed.get("rules_matched"));
    }

    // ---- Null matching ----

    public void testNullFieldMatch() throws Exception {
        String yaml = ruleYaml("Null Match", "    selection:\n        process.name: null");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"event\": {\"code\": 1}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        // Field is absent from flattened event, so event.get() returns null → matches SigmaNull
        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    // ---- Nested / flattened events ----

    public void testDeeplyNestedEvent() throws Exception {
        String yaml = ruleYaml("Deep Nested", "    selection:\n        a.b.c.d: value");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"a\": {\"b\": {\"c\": {\"d\": \"value\"}}}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    // ---- Multiple rules ----

    public void testMultipleRulesPartialMatch() throws Exception {
        String rule1Yaml = ruleYaml("Rule 1", "    selection:\n        process.name: cmd.exe");
        String rule2Yaml = ruleYaml("Rule 2", "    selection:\n        process.name: powershell.exe");
        SigmaRule rule1 = parseRule(rule1Yaml);
        SigmaRule rule2 = parseRule(rule2Yaml);
        String event = "{\"process\": {\"name\": \"cmd.exe\"}}";

        String result = matcher.evaluate(event, List.of(rule1, rule2));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(2, parsed.get("rules_evaluated"));
        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    public void testMultipleRulesBothMatch() throws Exception {
        String rule1Yaml = ruleYaml("Rule 1", "    selection:\n        process.name: cmd.exe");
        String rule2Yaml = ruleYaml("Rule 2", "    selection:\n        event.code: 4688");
        SigmaRule rule1 = parseRule(rule1Yaml);
        SigmaRule rule2 = parseRule(rule2Yaml);
        String event = "{\"process\": {\"name\": \"cmd.exe\"}, \"event\": {\"code\": 4688}}";

        String result = matcher.evaluate(event, List.of(rule1, rule2));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals(2, parsed.get("rules_evaluated"));
        Assert.assertEquals(2, parsed.get("rules_matched"));
    }

    // ---- Empty inputs ----

    public void testEmptyRuleList() throws Exception {
        String event = "{\"process\": {\"name\": \"cmd.exe\"}}";

        String result = matcher.evaluate(event, Collections.emptyList());
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(0, parsed.get("rules_evaluated"));
        Assert.assertEquals(0, parsed.get("rules_matched"));
    }

    public void testEmptyEvent() throws Exception {
        String yaml = ruleYaml("Empty Event", "    selection:\n        process.name: cmd.exe");
        SigmaRule rule = parseRule(yaml);
        String event = "{}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(0, parsed.get("rules_matched"));
    }

    // ---- Invalid JSON event ----

    public void testInvalidJsonReturnsError() throws Exception {
        String yaml = ruleYaml("Bad JSON", "    selection:\n        process.name: cmd.exe");
        SigmaRule rule = parseRule(yaml);
        String event = "not valid json";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals("error", parsed.get("status"));
    }

    // ---- OR condition ----

    public void testOrCondition() throws Exception {
        String yaml =
                String.join(
                        "\n",
                        "title: OR Test",
                        "status: test",
                        "logsource:",
                        "    category: test",
                        "detection:",
                        "    sel1:",
                        "        process.name: cmd.exe",
                        "    sel2:",
                        "        process.name: powershell.exe",
                        "    condition: sel1 or sel2",
                        "level: high");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"process\": {\"name\": \"powershell.exe\"}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);

        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    // ---- AND condition ----

    public void testAndCondition() throws Exception {
        String yaml =
                String.join(
                        "\n",
                        "title: AND Test",
                        "status: test",
                        "logsource:",
                        "    category: test",
                        "detection:",
                        "    sel1:",
                        "        process.name: cmd.exe",
                        "    sel2:",
                        "        event.code: 4688",
                        "    condition: sel1 and sel2",
                        "level: high");
        SigmaRule rule = parseRule(yaml);

        // Both fields present → match
        String event = "{\"process\": {\"name\": \"cmd.exe\"}, \"event\": {\"code\": 4688}}";
        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals(1, parsed.get("rules_matched"));

        // Only one field present → no match
        String event2 = "{\"process\": {\"name\": \"cmd.exe\"}, \"event\": {\"code\": 1111}}";
        String result2 = matcher.evaluate(event2, List.of(rule));
        Map<String, Object> parsed2 = MAPPER.readValue(result2, Map.class);
        Assert.assertEquals(0, parsed2.get("rules_matched"));
    }

    // ---- NOT condition ----

    public void testNotCondition() throws Exception {
        String yaml =
                String.join(
                        "\n",
                        "title: NOT Test",
                        "status: test",
                        "logsource:",
                        "    category: test",
                        "detection:",
                        "    sel1:",
                        "        process.name: cmd.exe",
                        "    filter:",
                        "        user.name: admin",
                        "    condition: sel1 and not filter",
                        "level: high");
        SigmaRule rule = parseRule(yaml);

        // Matches sel1 but not filter → overall match
        String event = "{\"process\": {\"name\": \"cmd.exe\"}, \"user\": {\"name\": \"jorge\"}}";
        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals(1, parsed.get("rules_matched"));

        // Matches sel1 AND filter → negated, so no match
        String event2 = "{\"process\": {\"name\": \"cmd.exe\"}, \"user\": {\"name\": \"admin\"}}";
        String result2 = matcher.evaluate(event2, List.of(rule));
        Map<String, Object> parsed2 = MAPPER.readValue(result2, Map.class);
        Assert.assertEquals(0, parsed2.get("rules_matched"));
    }

    // ---- Result structure ----

    @SuppressWarnings("unchecked")
    public void testResultContainsExpectedFields() throws Exception {
        String yaml =
                String.join(
                        "\n",
                        "title: Structure Test",
                        "id: 12345678-1234-1234-1234-123456789abc",
                        "status: test",
                        "logsource:",
                        "    category: test",
                        "detection:",
                        "    selection:",
                        "        process.name: cmd.exe",
                        "    condition: selection",
                        "level: critical",
                        "tags:",
                        "    - attack.execution",
                        "    - attack.t1059");
        SigmaRule rule = parseRule(yaml);
        String event = "{\"process\": {\"name\": \"cmd.exe\"}}";

        String result = matcher.evaluate(event, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        List<Map<String, Object>> matches = (List<Map<String, Object>>) parsed.get("matches");

        Assert.assertEquals(1, matches.size());
        Map<String, Object> match = matches.get(0);
        Assert.assertEquals("12345678-1234-1234-1234-123456789abc", match.get("rule_id"));
        Assert.assertEquals("Structure Test", match.get("rule_name"));
        Assert.assertEquals("critical", match.get("severity"));
        Assert.assertNotNull(match.get("matched_conditions"));
        Assert.assertNotNull(match.get("tags"));

        List<String> tags = (List<String>) match.get("tags");
        Assert.assertTrue(tags.contains("attack.execution"));
        Assert.assertTrue(tags.contains("attack.t1059"));
    }
}
