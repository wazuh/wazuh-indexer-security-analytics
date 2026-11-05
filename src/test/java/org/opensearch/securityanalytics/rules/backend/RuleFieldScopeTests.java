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
package org.opensearch.securityanalytics.rules.backend;

import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.model.RuleMetadata;
import org.opensearch.securityanalytics.model.Value;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.test.OpenSearchTestCase;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Covers how a rule's reach over the fields of an event is told apart. */
public class RuleFieldScopeTests extends OpenSearchTestCase {

    private static String yaml(String detection) {
        return String.join(
                "\n",
                "title: Scope",
                "id: 11111111-1111-1111-1111-111111111111",
                "status: test",
                "logsource:",
                "    product: test",
                "detection:",
                detection,
                "level: high",
                "metadata:",
                "    title: Scope",
                "    author: Wazuh, Inc.",
                "    date: '2026-09-04'");
    }

    /** Stores a rule the way rule upload does, with the field names its compilation records. */
    private static Rule stored(String detection) throws Exception {
        String body = yaml(detection);
        SigmaRule parsed = SigmaRule.fromYaml(body, true);
        RuleFieldScope.Backend backend = new RuleFieldScope.Backend();
        List<Object> queries = backend.convertRule(parsed);
        return new Rule(
                "rule-1",
                1L,
                parsed,
                "test",
                queries,
                new ArrayList<>(backend.getQueryFields().keySet()),
                body);
    }

    public void testAKeywordsListMatchesAnyField() throws Exception {
        assertTrue(
                RuleFieldScope.matchesAnyField(
                        stored(
                                "    keywords:\n        - DataError\n        - '*Timeout*'\n    condition: keywords")));
    }

    public void testAKeywordCombinedWithASelectionMatchesAnyField() throws Exception {
        // The rule names a field, so its field names alone do not reveal the keyword.
        Rule rule =
                stored(
                        "    keywords:\n        - DataError\n    selection:\n        event.kind: event\n"
                                + "    condition: keywords and selection");
        assertFalse("the selection's field is recorded", rule.getQueryFieldNames().isEmpty());
        assertTrue(RuleFieldScope.matchesAnyField(rule));
    }

    public void testANegatedKeywordStillMatchesAnyField() throws Exception {
        assertTrue(
                RuleFieldScope.matchesAnyField(
                        stored(
                                "    keywords:\n        - DataError\n    selection:\n        event.kind: event\n"
                                        + "    condition: selection and not keywords")));
    }

    public void testASelectionOnlyMatchesTheFieldsItNames() throws Exception {
        assertFalse(
                RuleFieldScope.matchesAnyField(
                        stored(
                                "    selection:\n        event.kind: event\n        message|contains: fatal\n"
                                        + "    condition: selection")));
    }

    public void testARuleThatCannotBeReadKeepsItsFieldNames() {
        Rule rule =
                new Rule(
                        "rule-1",
                        1L,
                        "test",
                        "test",
                        Collections.<Value>emptyList(),
                        Collections.<Value>emptyList(),
                        "high",
                        Collections.<Value>emptyList(),
                        "test",
                        Instant.now(),
                        List.of(new Value("event.kind: \"event\"")),
                        List.of(new Value("event.kind")),
                        "not: [a, sigma, rule",
                        Collections.<Value>emptyList(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        RuleMetadata.empty());
        assertFalse(RuleFieldScope.matchesAnyField(rule));
    }

    public void testTheBackendForgetsThePreviousRule() throws Exception {
        RuleFieldScope.Backend backend = new RuleFieldScope.Backend();
        backend.convertRule(
                SigmaRule.fromYaml(
                        yaml("    keywords:\n        - DataError\n    condition: keywords"), true));
        assertTrue(backend.matchesAnyField());
        backend.convertRule(
                SigmaRule.fromYaml(
                        yaml("    selection:\n        event.kind: event\n    condition: selection"), true));
        assertFalse(backend.matchesAnyField());
    }

    public void testTheBackendCompilesExactlyAsRuleUploadDoes() throws Exception {
        String body =
                yaml(
                        "    keywords:\n        - DataError\n    selection:\n        event.kind: event\n"
                                + "    condition: keywords and selection");
        assertEquals(
                new OSQueryBackend(Collections.emptyMap(), false)
                        .convertRule(SigmaRule.fromYaml(body, true)),
                new RuleFieldScope.Backend().convertRule(SigmaRule.fromYaml(body, true)));
    }
}
