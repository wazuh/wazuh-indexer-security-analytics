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

import org.opensearch.test.OpenSearchTestCase;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Covers the naming and mapping-copy rules of the logtest percolator index. */
public class LogtestQueryIndexTests extends OpenSearchTestCase {

    public void testIndexNameIsDerivedFromLogType() {
        assertEquals(
                ".opensearch-sap-apache-detectors-queries-logtest", LogtestQueryIndex.indexName("apache"));
    }

    public void testIndexNameSanitizesLogType() {
        // Integration titles are free text; an index name is not.
        assertEquals(
                ".opensearch-sap-microsoft_intune-detectors-queries-logtest",
                LogtestQueryIndex.indexName("Microsoft Intune"));
        assertEquals(
                ".opensearch-sap-aws_cloudtrail-detectors-queries-logtest",
                LogtestQueryIndex.indexName("AWS/CloudTrail"));
    }

    public void testIndexNameStaysInsideTheQueryIndexTemplatePattern() {
        // The whole point of the name: matching .opensearch-sap-*-detectors-queries* is what makes
        // the index inherit rule_analyzer and rule_ws_normalizer.
        String name = LogtestQueryIndex.indexName("apache");
        assertTrue(name, name.startsWith(".opensearch-sap-"));
        assertTrue(name, name.contains("-detectors-queries"));
    }

    public void testAnalysisOverridesReachNestedLeaves() {
        Map<String, Object> properties =
                mutable(
                        Map.of(
                                "url",
                                mutable(
                                        Map.of(
                                                "properties",
                                                mutable(Map.of("original", mutable(Map.of("type", "keyword")))))),
                                "message",
                                mutable(Map.of("type", "text")),
                                "event",
                                mutable(
                                        Map.of(
                                                "properties",
                                                mutable(Map.of("duration", mutable(Map.of("type", "long"))))))));

        LogtestQueryIndex.applyAnalysisOverrides(properties);

        assertEquals("rule_ws_normalizer", leaf(properties, "url", "original").get("normalizer"));
        assertEquals("rule_analyzer", leaf(properties, "message").get("analyzer"));
        // Numeric fields need no analysis, and giving them any would break the mapping.
        assertNull(leaf(properties, "event", "duration").get("normalizer"));
        assertNull(leaf(properties, "event", "duration").get("analyzer"));
    }

    public void testNestedContainersKeepTheirType() {
        Map<String, Object> properties =
                mutable(
                        Map.of(
                                "related",
                                mutable(
                                        Map.of(
                                                "type",
                                                "nested",
                                                "properties",
                                                mutable(Map.of("user", mutable(Map.of("type", "keyword"))))))));

        LogtestQueryIndex.applyAnalysisOverrides(properties);

        Map<String, Object> related = leaf(properties, "related");
        assertEquals("nested", related.get("type"));
        assertNull("a nested container is not a leaf to analyze", related.get("normalizer"));
        assertEquals("rule_ws_normalizer", leaf(properties, "related", "user").get("normalizer"));
    }

    public void testMergeKeepsTheFirstMappingOfAConflictingField() {
        Map<String, Object> target = mutable(Map.of("host", mutable(Map.of("type", "keyword"))));
        Map<String, Object> source = mutable(Map.of("host", mutable(Map.of("type", "text"))));

        LogtestQueryIndex.mergeProperties(source, target, "wazuh-events-v5-other");

        assertEquals("keyword", leaf(target, "host").get("type"));
    }

    public void testMergeUnionsFieldsAcrossSourceIndices() {
        Map<String, Object> target =
                mutable(
                        Map.of(
                                "url",
                                mutable(
                                        Map.of(
                                                "properties",
                                                mutable(Map.of("original", mutable(Map.of("type", "keyword"))))))));
        Map<String, Object> source =
                mutable(
                        Map.of(
                                "url",
                                mutable(
                                        Map.of(
                                                "properties", mutable(Map.of("path", mutable(Map.of("type", "keyword")))))),
                                "message",
                                mutable(Map.of("type", "text"))));

        LogtestQueryIndex.mergeProperties(source, target, "wazuh-events-v5-web");

        assertEquals("keyword", leaf(target, "url", "original").get("type"));
        assertEquals("keyword", leaf(target, "url", "path").get("type"));
        assertEquals("text", leaf(target, "message").get("type"));
    }

    public void testMergeDoesNotAliasTheSourceMapping() {
        // The source is cluster state; rewriting it in place would corrupt an index's mapping view.
        Map<String, Object> source = mutable(Map.of("message", mutable(Map.of("type", "text"))));
        Map<String, Object> target = new HashMap<>();

        LogtestQueryIndex.mergeProperties(source, target, "wazuh-events-v5-web");
        LogtestQueryIndex.applyAnalysisOverrides(target);

        assertEquals("rule_analyzer", leaf(target, "message").get("analyzer"));
        assertNull(leaf(source, "message").get("analyzer"));
    }

    /** Deep-copies an immutable literal map into a mutable one, as a real mapping tree is. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> mutable(Map<String, Object> source) {
        Map<String, Object> copy = new HashMap<>();
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            copy.put(
                    entry.getKey(),
                    entry.getValue() instanceof Map
                            ? mutable((Map<String, Object>) entry.getValue())
                            : entry.getValue());
        }
        return copy;
    }

    /** Walks a mapping tree to the leaf named by the given path. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> leaf(Map<String, Object> properties, String... path) {
        Map<String, Object> current = properties;
        for (int i = 0; i < path.length; i++) {
            current = (Map<String, Object>) current.get(path[i]);
            assertNotNull(path[i], current);
            if (i < path.length - 1) {
                current = (Map<String, Object>) current.get("properties");
                assertNotNull(path[i] + ".properties", current);
            }
        }
        return current;
    }

    // ---- fields declared by a dynamic template but not yet materialized ----

    /**
     * The WCS event templates declare fields this way; a field is real only once a doc carries it.
     */
    private static List<Map<String, Object>> wcsTemplates() {
        return List.of(
                Map.of(
                        "wcs_url_original",
                        Map.of(
                                "path_match",
                                "url.original",
                                "mapping",
                                Map.of("type", "keyword", "ignore_above", 1024))),
                Map.of(
                        "wcs_http_request_method",
                        Map.of(
                                "path_match",
                                "http.request.method",
                                "mapping",
                                Map.of("type", "keyword", "ignore_above", 1024))),
                Map.of(
                        "wcs_labels", Map.of("path_match", "labels.*", "mapping", Map.of("type", "keyword"))));
    }

    public void testARequiredFieldDeclaredByATemplateIsMapped() {
        // The reported failure: an integration whose events have not been ingested has nothing
        // materialized, so every rule was rejected even though a detector would match once data
        // arrives.
        Map<String, Object> properties = new HashMap<>();

        LogtestQueryIndex.declareFieldsFromDynamicTemplates(
                properties, Set.of("url.original", "http.request.method"), wcsTemplates());

        assertEquals("keyword", leaf(properties, "url", "original").get("type"));
        assertEquals("keyword", leaf(properties, "http", "request", "method").get("type"));
    }

    public void testADeclaredFieldGetsTheQueryIndexAnalysisChain() {
        // Mapping the field is only half of it: without the normalizer a value containing a space
        // still would not match.
        Map<String, Object> properties = new HashMap<>();
        LogtestQueryIndex.declareFieldsFromDynamicTemplates(
                properties, Set.of("url.original"), wcsTemplates());

        LogtestQueryIndex.applyAnalysisOverrides(properties);

        assertEquals("rule_ws_normalizer", leaf(properties, "url", "original").get("normalizer"));
    }

    public void testAFieldDeclaredNowhereStaysUnmapped() {
        // The percolator must still refuse these, because that refusal is a true statement about
        // what a detector can match.
        Map<String, Object> properties = new HashMap<>();

        LogtestQueryIndex.declareFieldsFromDynamicTemplates(
                properties, Set.of("not.a.wcs.field"), wcsTemplates());

        assertTrue("nothing should have been declared", properties.isEmpty());
    }

    public void testAMaterializedFieldIsNotOverwritten() {
        // The source index owns its real mappings; a template must not replace one.
        Map<String, Object> properties = new HashMap<>();
        properties.put(
                "url",
                Map.of(
                        "properties",
                        new HashMap<>(Map.of("original", new HashMap<>(Map.of("type", "text"))))));

        LogtestQueryIndex.declareFieldsFromDynamicTemplates(
                properties, Set.of("url.original"), wcsTemplates());

        assertEquals("text", leaf(properties, "url", "original").get("type"));
    }

    public void testPathMatchSupportsWildcardsWithinASegment() {
        assertTrue(LogtestQueryIndex.pathMatches("url.original", "url.original"));
        assertFalse(LogtestQueryIndex.pathMatches("url.original", "url.originaly"));
        assertTrue(LogtestQueryIndex.pathMatches("labels.*", "labels.env"));
        // `*` must not cross a dot, matching OpenSearch's own path_match semantics.
        assertFalse(LogtestQueryIndex.pathMatches("labels.*", "labels.env.name"));
    }

    public void testIsMappedWalksNestedPaths() {
        Map<String, Object> properties = new HashMap<>();
        LogtestQueryIndex.declareField(properties, "http.request.method", Map.of("type", "keyword"));

        assertTrue(LogtestQueryIndex.isMapped(properties, "http.request.method"));
        assertFalse(LogtestQueryIndex.isMapped(properties, "http.request.referrer"));
        assertFalse(LogtestQueryIndex.isMapped(properties, "http.response"));
    }

    public void testAnEmptyObjectContainerIsGivenChildren() {
        // OpenSearch renders a container with no children as {"type":"object"} and no `properties`
        // key. That is what every unpopulated WCS container looks like, and mistaking it for a leaf
        // is why url.original stayed unmapped while http.request.method was fine.
        Map<String, Object> properties = new HashMap<>();
        properties.put("url", new HashMap<>(Map.of("type", "object")));

        LogtestQueryIndex.declareFieldsFromDynamicTemplates(
                properties, Set.of("url.original"), wcsTemplates());

        assertEquals("keyword", leaf(properties, "url", "original").get("type"));
    }

    public void testARealLeafIsNotTurnedIntoAContainer() {
        // If the source maps `url` itself as a keyword, a rule on url.original disagrees with the
        // source and we must not rewrite the source's mapping.
        Map<String, Object> properties = new HashMap<>();
        properties.put("url", new HashMap<>(Map.of("type", "keyword")));

        LogtestQueryIndex.declareFieldsFromDynamicTemplates(
                properties, Set.of("url.original"), wcsTemplates());

        assertEquals("keyword", ((Map<?, ?>) properties.get("url")).get("type"));
        assertNull(((Map<?, ?>) properties.get("url")).get("properties"));
    }
}
