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
import java.util.LinkedHashMap;
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
        Map<String, Object> ruleInfo = (Map<String, Object>) match.get("rule");
        Assert.assertNotNull(ruleInfo);
        Assert.assertEquals("12345678-1234-1234-1234-123456789abc", ruleInfo.get("id"));
        Assert.assertEquals("Structure Test", ruleInfo.get("title"));
        Assert.assertEquals("critical", ruleInfo.get("level"));
        Assert.assertNotNull(match.get("matched_conditions"));

        List<String> tags = (List<String>) ruleInfo.get("tags");
        Assert.assertNotNull(tags);
        Assert.assertTrue(tags.contains("attack.execution"));
        Assert.assertTrue(tags.contains("attack.t1059"));
    }

    // ---- Startswith / Endswith / Contains modifiers ----

    // spotless:off

    /** Full normalized event from the Wazuh Engine (Cassandra decoder). */
    private static final String CASSANDRA_EVENT = """
        {
          "wazuh": {
            "integration": {"category": "other", "decoders": ["decoder/cassandra-default/0"], "name": "hola-12345"},
            "protocol": {"queue": 1, "location": "/var/log/cassandra/system.log"},
            "space": {"name": "test"}
          },
          "process": {"command_line": "/query tables", "thread": {"name": "CompactionExecutor-3"}},
          "event": {"severity": 1, "kind": "event", "category": ["database"],
            "original": "INFO  [CompactionExecutor-3] 2025-11-30 14:23:45 CassandraDaemon.java:250 - Some message - 100 - 1",
            "duration": 100, "type": ["info"]},
          "log": {"level": "INFO", "origin": {"file": {"name": "CassandraDaemon.java", "line": 250}}},
          "source": {"ip": "10.42.3.15"},
          "message": "Some message"
        }
        """;

    /**
     * Builds a rule JSON in the same format stored in the wazuh-threatintel-rules index
     * (after nestMetadataFields processing).
     */
    private static String indexedRuleJson(String id, String title, String level, String detectionField, String detectionValue) {
        return String.format(
                """
                {
                  "id": "%s",
                  "logsource": {"product": "hola-12345"},
                  "metadata": {
                    "title": "%s",
                    "description": "Test rule",
                    "references": [],
                    "author": "Wazuh",
                    "date": "2026-04-14",
                    "modified": "2026-04-14",
                    "supports": []
                  },
                  "tags": ["attack.execution", "attack.t1059"],
                  "falsepositives": ["Testing"],
                  "level": "%s",
                  "status": "test",
                  "enabled": true,
                  "detection": {
                    "condition": "selection",
                    "selection": {
                      "%s": %s
                    }
                  }
                }
                """,
                id, title, level, detectionField, detectionValue);
    }
    // spotless:on

    // ---- YAML-based modifier tests ----

    public void testStartswithMatch() throws Exception {
        String yaml =
                ruleYaml(
                        "Startswith", "    selection:\n        process.thread.name|startswith: Compaction");
        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(parseRule(yaml)));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    public void testStartswithNoMatch() throws Exception {
        String yaml =
                ruleYaml(
                        "Startswith No Match",
                        "    selection:\n        process.thread.name|startswith: Native");
        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(parseRule(yaml)));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals(0, parsed.get("rules_matched"));
    }

    public void testEndswithMatch() throws Exception {
        String yaml =
                ruleYaml("Endswith", "    selection:\n        process.thread.name|endswith: \"3\"");
        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(parseRule(yaml)));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    public void testEndswithNoMatch() throws Exception {
        String yaml =
                ruleYaml(
                        "Endswith No Match", "    selection:\n        process.thread.name|endswith: \"7\"");
        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(parseRule(yaml)));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals(0, parsed.get("rules_matched"));
    }

    public void testContainsMatch() throws Exception {
        String yaml = ruleYaml("Contains", "    selection:\n        message|contains: \"Some\"");
        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(parseRule(yaml)));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals(1, parsed.get("rules_matched"));
    }

    public void testContainsNoMatch() throws Exception {
        String yaml =
                ruleYaml("Contains No Match", "    selection:\n        message|contains: \"error\"");
        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(parseRule(yaml)));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals(0, parsed.get("rules_matched"));
    }

    // ---- JSON-based tests (simulating wazuh-threatintel-rules index round-trip) ----

    /**
     * Startswith parsed from JSON (Content Manager stored format). Verifies the full round-trip: JSON
     * document → SigmaRule.fromYaml → EventMatcher.
     */
    @SuppressWarnings("unchecked")
    public void testStartswithFromIndexedJson() throws Exception {
        String ruleJson =
                indexedRuleJson(
                        "12345678-1234-1234-1234-123456789abc",
                        "TEST: Startswith only",
                        "high",
                        "process.thread.name|startswith",
                        "\"Compaction\"");

        SigmaRule rule = SigmaRule.fromYaml(ruleJson, true);
        Assert.assertNotNull("Detection should be parsed", rule.getDetection());
        Assert.assertFalse(
                "Parsed conditions should not be empty",
                rule.getDetection().getParsedCondition().isEmpty());

        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(1, ((Number) parsed.get("rules_evaluated")).intValue());
        Assert.assertEquals(1, ((Number) parsed.get("rules_matched")).intValue());

        List<Map<String, Object>> matches = (List<Map<String, Object>>) parsed.get("matches");
        Map<String, Object> ruleInfo = (Map<String, Object>) matches.get(0).get("rule");
        Assert.assertEquals("12345678-1234-1234-1234-123456789abc", ruleInfo.get("id"));
        Assert.assertEquals("TEST: Startswith only", ruleInfo.get("title"));

        List<String> conditions = (List<String>) matches.get(0).get("matched_conditions");
        Assert.assertTrue(
                "Should mention the matched field", conditions.get(0).contains("process.thread.name"));
    }

    /** Endswith parsed from JSON (Content Manager stored format). */
    public void testEndswithFromIndexedJson() throws Exception {
        String ruleJson =
                indexedRuleJson(
                        "22345678-1234-1234-1234-123456789abc",
                        "TEST: Endswith only",
                        "medium",
                        "process.thread.name|endswith",
                        "\"3\"");

        SigmaRule rule = SigmaRule.fromYaml(ruleJson, true);
        Assert.assertNotNull("Detection should be parsed", rule.getDetection());

        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(1, ((Number) parsed.get("rules_matched")).intValue());
    }

    /** Contains parsed from JSON (Content Manager stored format). */
    public void testContainsFromIndexedJson() throws Exception {
        String ruleJson =
                indexedRuleJson(
                        "32345678-1234-1234-1234-123456789abc",
                        "TEST: Contains only",
                        "low",
                        "message|contains",
                        "\"Some\"");

        SigmaRule rule = SigmaRule.fromYaml(ruleJson, true);
        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals(1, ((Number) parsed.get("rules_matched")).intValue());
    }

    /**
     * Jackson Map round-trip: simulates the exact path in fetchRuleBodies (getSourceAsMap → Jackson
     * writeValueAsString → SigmaRule.fromYaml).
     */
    @SuppressWarnings("unchecked")
    public void testStartswithJacksonRoundTrip() throws Exception {
        // 1. Build the document as a Java Map (like getSourceAsMap returns)
        Map<String, Object> selection = new LinkedHashMap<>();
        selection.put("process.thread.name|startswith", "Compaction");

        Map<String, Object> detection = new LinkedHashMap<>();
        detection.put("condition", "selection");
        detection.put("selection", selection);

        Map<String, Object> logsource = new LinkedHashMap<>();
        logsource.put("product", "hola-12345");

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("title", "Jackson Round-Trip Test");
        metadata.put("description", "test");
        metadata.put("references", List.of());
        metadata.put("author", "Wazuh");
        metadata.put("date", "2026-04-14");
        metadata.put("modified", "2026-04-14");
        metadata.put("supports", List.of());

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("id", "42345678-1234-1234-1234-123456789abc");
        document.put("logsource", logsource);
        document.put("metadata", metadata);
        document.put("tags", List.of("attack.execution"));
        document.put("falsepositives", List.of("Testing"));
        document.put("level", "high");
        document.put("status", "test");
        document.put("enabled", true);
        document.put("detection", detection);

        // 2. Serialize with Jackson (same as fetchRuleBodies does)
        String ruleBody = MAPPER.writeValueAsString(document);

        // 3. Parse with SigmaRule.fromYaml (same as WTransportEvaluateRulesAction)
        SigmaRule rule = SigmaRule.fromYaml(ruleBody, true);
        Assert.assertNotNull("Detection must be parsed", rule.getDetection());

        // 4. Evaluate (same as EventMatcher.evaluate in SAP)
        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(1, ((Number) parsed.get("rules_evaluated")).intValue());
        Assert.assertEquals(1, ((Number) parsed.get("rules_matched")).intValue());
    }

    /** Same Jackson round-trip for endswith. */
    @SuppressWarnings("unchecked")
    public void testEndswithJacksonRoundTrip() throws Exception {
        Map<String, Object> selection = new LinkedHashMap<>();
        selection.put("process.thread.name|endswith", "3");

        Map<String, Object> detection = new LinkedHashMap<>();
        detection.put("condition", "selection");
        detection.put("selection", selection);

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("id", "52345678-1234-1234-1234-123456789abc");
        document.put("logsource", Map.of("product", "hola-12345"));
        document.put("metadata", Map.of("title", "Endswith Round-Trip", "author", "Wazuh"));
        document.put("level", "medium");
        document.put("status", "test");
        document.put("enabled", true);
        document.put("detection", detection);

        String ruleBody = MAPPER.writeValueAsString(document);
        SigmaRule rule = SigmaRule.fromYaml(ruleBody, true);
        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(rule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(1, ((Number) parsed.get("rules_matched")).intValue());
    }

    /**
     * Multiple rules evaluated together: startswith matches, endswith matches, contains does NOT
     * match. Verifies selective matching in a batch.
     */
    @SuppressWarnings("unchecked")
    public void testMultipleModifierRulesMixed() throws Exception {
        SigmaRule startsRule =
                SigmaRule.fromYaml(
                        indexedRuleJson(
                                "62345678-1234-1234-1234-123456789abc",
                                "Startswith Rule",
                                "high",
                                "process.thread.name|startswith",
                                "\"Compaction\""),
                        true);
        SigmaRule endsRule =
                SigmaRule.fromYaml(
                        indexedRuleJson(
                                "72345678-1234-1234-1234-123456789abc",
                                "Endswith Rule",
                                "medium",
                                "process.thread.name|endswith",
                                "\"3\""),
                        true);
        SigmaRule containsRule =
                SigmaRule.fromYaml(
                        indexedRuleJson(
                                "82345678-1234-1234-1234-123456789abc",
                                "Contains Rule",
                                "low",
                                "message|contains",
                                "\"error\""),
                        true);

        String result = matcher.evaluate(CASSANDRA_EVENT, List.of(startsRule, endsRule, containsRule));
        Map<String, Object> parsed = MAPPER.readValue(result, Map.class);
        Assert.assertEquals("success", parsed.get("status"));
        Assert.assertEquals(3, ((Number) parsed.get("rules_evaluated")).intValue());
        Assert.assertEquals(2, ((Number) parsed.get("rules_matched")).intValue());

        List<Map<String, Object>> matches = (List<Map<String, Object>>) parsed.get("matches");
        List<String> matchedTitles =
                matches.stream()
                        .map(m -> ((Map<String, Object>) m.get("rule")).get("title").toString())
                        .sorted()
                        .toList();
        Assert.assertEquals(List.of("Endswith Rule", "Startswith Rule"), matchedTitles);
    }
}
