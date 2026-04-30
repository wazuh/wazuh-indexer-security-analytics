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
package org.opensearch.securityanalytics.enrichment;

import org.opensearch.test.OpenSearchTestCase;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class TemplateInterpolatorTests extends OpenSearchTestCase {

    // ── interpolate (String) ────────────────────────────────────────────────

    public void testSinglePlaceholder() {
        Map<String, Object> source = Map.of("wazuh", Map.of("agent", Map.of("id", "001")));
        assertEquals(
                "Agent 001", TemplateInterpolator.interpolate("Agent {{ wazuh.agent.id }}", source));
    }

    public void testMultiplePlaceholders() {
        Map<String, Object> source = Map.of("a", "foo", "b", "bar");
        assertEquals("foo and bar", TemplateInterpolator.interpolate("{{ a }} and {{ b }}", source));
    }

    public void testNumericCoercion() {
        Map<String, Object> source = Map.of("count", 42);
        assertEquals("count=42", TemplateInterpolator.interpolate("count={{ count }}", source));
    }

    public void testBooleanCoercion() {
        Map<String, Object> source = Map.of("flag", true);
        assertEquals("true", TemplateInterpolator.interpolate("{{ flag }}", source));
    }

    public void testMissingField() {
        Map<String, Object> source = Map.of();
        assertEquals("Hello ", TemplateInterpolator.interpolate("Hello {{ missing }}", source));
    }

    public void testNullField() {
        Map<String, Object> source = new HashMap<>();
        source.put("x", null);
        assertEquals("Hello ", TemplateInterpolator.interpolate("Hello {{ x }}", source));
    }

    public void testNonScalarMap() {
        Map<String, Object> source = Map.of("obj", Map.of("a", 1));
        assertEquals("", TemplateInterpolator.interpolate("{{ obj }}", source));
    }

    public void testNonScalarList() {
        Map<String, Object> source = Map.of("arr", List.of("a", "b"));
        assertEquals("", TemplateInterpolator.interpolate("{{ arr }}", source));
    }

    public void testWhitespaceTrimming() {
        Map<String, Object> source = Map.of("wazuh", Map.of("agent", Map.of("id", "001")));
        assertEquals("001", TemplateInterpolator.interpolate("{{  wazuh.agent.id  }}", source));
    }

    public void testNoPlaceholders() {
        assertEquals("plain text", TemplateInterpolator.interpolate("plain text", Map.of()));
    }

    public void testNullInput() {
        assertNull(TemplateInterpolator.interpolate(null, Map.of()));
    }

    public void testNullSource() {
        assertEquals("{{ x }}", TemplateInterpolator.interpolate("{{ x }}", null));
    }

    // ── interpolateList ─────────────────────────────────────────────────────

    public void testListPlainStrings() {
        List<String> result = TemplateInterpolator.interpolateList(Arrays.asList("a", "b"), Map.of());
        assertEquals(List.of("a", "b"), result);
    }

    public void testListDropsEmptyResolution() {
        List<String> result =
                TemplateInterpolator.interpolateList(Arrays.asList("{{ missing }}"), Map.of());
        assertEquals(List.of(), result);
    }

    public void testListArrayExpansion() {
        Map<String, Object> source =
                Map.of("check", Map.of("compliance", Map.of("pci_dss", List.of("2.2.1", "6.3.3"))));
        List<String> result =
                TemplateInterpolator.interpolateList(
                        Arrays.asList("6.2", "{{ check.compliance.pci_dss }}"), source);
        assertEquals(List.of("6.2", "2.2.1", "6.3.3"), result);
    }

    public void testListScalarExpansion() {
        Map<String, Object> source = Map.of("val", "x");
        List<String> result = TemplateInterpolator.interpolateList(Arrays.asList("{{ val }}"), source);
        assertEquals(List.of("x"), result);
    }

    public void testListDeduplication() {
        Map<String, Object> source = Map.of("vals", List.of("6.2", "11.4"));
        List<String> result =
                TemplateInterpolator.interpolateList(Arrays.asList("6.2", "{{ vals }}"), source);
        assertEquals(List.of("6.2", "11.4"), result);
    }

    public void testListMixedTextPlaceholder() {
        Map<String, Object> source = Map.of("name", "web");
        List<String> result =
                TemplateInterpolator.interpolateList(Arrays.asList("tag-{{ name }}"), source);
        assertEquals(List.of("tag-web"), result);
    }

    public void testListMixedTextDropsEmpty() {
        List<String> result =
                TemplateInterpolator.interpolateList(
                        Arrays.asList("prefix-{{ missing }}-suffix"), Map.of());
        // Mixed text with missing field produces "prefix--suffix", which is non-empty → kept
        assertEquals(List.of("prefix--suffix"), result);
    }

    public void testListNullInput() {
        assertNull(TemplateInterpolator.interpolateList(null, Map.of()));
    }

    public void testListEmptyInput() {
        assertEquals(List.of(), TemplateInterpolator.interpolateList(List.of(), Map.of()));
    }

    public void testListPurePlaceholderResolvesToMap() {
        Map<String, Object> source = Map.of("obj", Map.of("a", 1));
        List<String> result =
                TemplateInterpolator.interpolateList(Arrays.asList("keep", "{{ obj }}"), source);
        assertEquals(List.of("keep"), result);
    }

    public void testListArrayExpansionWithNumericElements() {
        Map<String, Object> source = Map.of("nums", List.of(1, 2, 3));
        List<String> result = TemplateInterpolator.interpolateList(Arrays.asList("{{ nums }}"), source);
        assertEquals(List.of("1", "2", "3"), result);
    }

    // ── interpolateMapOfLists ───────────────────────────────────────────────

    public void testMapOfListsInterpolation() {
        Map<String, Object> source = Map.of("x", List.of("2.2.1"));
        Map<String, List<String>> map = new LinkedHashMap<>();
        map.put("pci_dss", new ArrayList<>(Arrays.asList("6.2", "{{ x }}")));
        Map<String, List<String>> result = TemplateInterpolator.interpolateMapOfLists(map, source);
        assertEquals(Map.of("pci_dss", List.of("6.2", "2.2.1")), result);
    }

    public void testMapOfListsDropsEmptyKey() {
        Map<String, List<String>> map = new LinkedHashMap<>();
        map.put("gdpr", new ArrayList<>(Arrays.asList("{{ missing }}")));
        map.put("pci_dss", new ArrayList<>(Arrays.asList("6.2")));
        Map<String, List<String>> result = TemplateInterpolator.interpolateMapOfLists(map, Map.of());
        assertEquals(Map.of("pci_dss", List.of("6.2")), result);
    }

    public void testMapOfListsNullInput() {
        assertNull(TemplateInterpolator.interpolateMapOfLists(null, Map.of()));
    }

    public void testMapOfListsEmptyInput() {
        assertEquals(Map.of(), TemplateInterpolator.interpolateMapOfLists(Map.of(), Map.of()));
    }

    public void testMapOfListsFullCompliance() {
        Map<String, Object> source =
                Map.of("check", Map.of("compliance", Map.of("pci_dss", List.of("2.2.1", "6.3.3"))));
        Map<String, List<String>> map = new LinkedHashMap<>();
        map.put(
                "pci_dss", new ArrayList<>(Arrays.asList("6.2", "11.4", "{{ check.compliance.pci_dss }}")));
        Map<String, List<String>> result = TemplateInterpolator.interpolateMapOfLists(map, source);
        assertEquals(List.of("6.2", "11.4", "2.2.1", "6.3.3"), result.get("pci_dss"));
    }

    // ── resolvePath ─────────────────────────────────────────────────────────

    public void testResolvePathDeepNesting() {
        Map<String, Object> source = Map.of("a", Map.of("b", Map.of("c", "deep")));
        assertEquals("deep", TemplateInterpolator.resolvePath("a.b.c", source));
    }

    public void testResolvePathTopLevel() {
        Map<String, Object> source = Map.of("key", "val");
        assertEquals("val", TemplateInterpolator.resolvePath("key", source));
    }

    public void testResolvePathMissing() {
        assertNull(TemplateInterpolator.resolvePath("a.b.c", Map.of()));
    }

    public void testResolvePathPartialMissing() {
        Map<String, Object> source = Map.of("a", Map.of("x", 1));
        assertNull(TemplateInterpolator.resolvePath("a.b.c", source));
    }

    public void testResolvePathNullSource() {
        assertNull(TemplateInterpolator.resolvePath("a", null));
    }

    public void testResolvePathEmptyPath() {
        assertNull(TemplateInterpolator.resolvePath("", Map.of("a", 1)));
    }

    public void testResolvePathNullPath() {
        assertNull(TemplateInterpolator.resolvePath(null, Map.of("a", 1)));
    }
}
