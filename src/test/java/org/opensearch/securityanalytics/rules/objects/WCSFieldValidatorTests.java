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
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.Version;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;

import java.io.IOException;
import java.util.List;

public class WCSFieldValidatorTests extends OpenSearchTestCase {

    /** Events mapping: one field from a dynamic template, one from the properties. */
    private static final String EVENTS_MAPPING =
            "{\"dynamic\":\"strict_allow_templates\","
                    + "\"dynamic_templates\":[{\"event.dataset\":{\"path_match\":\"event.dataset\","
                    + "\"mapping\":{\"type\":\"keyword\"}}}],"
                    + "\"properties\":{\"wazuh\":{\"properties\":{\"agent\":{\"properties\":"
                    + "{\"name\":{\"type\":\"keyword\"}}}}}}}";

    /** The events mapping plus event.action. */
    private static final String EVENTS_MAPPING_WITH_ACTION =
            EVENTS_MAPPING.replace(
                    "\"properties\":{\"wazuh\"",
                    "\"properties\":{\"event\":{\"properties\":{\"action\":{\"type\":\"keyword\"}}},\"wazuh\"");

    /** Raw events mapping: strict, a handful of fields, none of the events-only ones. */
    private static final String RAW_MAPPING =
            "{\"dynamic\":\"strict\",\"properties\":{\"event\":{\"properties\":"
                    + "{\"original\":{\"type\":\"keyword\"}}}}}";

    @After
    public void resetValidator() {
        WCSFieldValidator.reset();
    }

    public void testIgnoresRawEventsTemplateAndBackingIndices() throws IOException {
        WCSFieldValidator.initFromMetadata(
                Metadata.builder()
                        .put("wazuh-events-raw-v5-template", template(RAW_MAPPING))
                        .put(backingIndex(".ds-wazuh-events-raw-v5-000040", RAW_MAPPING), false)
                        .build());

        assertFalse(WCSFieldValidator.isInitialized());
    }

    public void testLoadsFieldsFromEventsTemplate() throws IOException {
        WCSFieldValidator.initFromMetadata(
                Metadata.builder()
                        .put("wazuh-events-raw-v5-template", template(RAW_MAPPING))
                        .put(backingIndex(".ds-wazuh-events-raw-v5-000040", RAW_MAPPING), false)
                        .put("wazuh-events-v5-other-template", template(EVENTS_MAPPING))
                        .build());

        assertTrue(WCSFieldValidator.isWCSField("event.dataset"));
        assertTrue(WCSFieldValidator.isWCSField("wazuh.agent.name"));
        assertFalse(WCSFieldValidator.isWCSField("event.original"));
    }

    public void testReloadsWhenEventsTemplateMappingChanges() throws IOException {
        WCSFieldValidator.initFromMetadata(
                Metadata.builder().put("wazuh-events-v5-other-template", template(EVENTS_MAPPING)).build());
        assertFalse(WCSFieldValidator.isWCSField("event.action"));

        WCSFieldValidator.initFromMetadata(
                Metadata.builder()
                        .put("wazuh-events-v5-other-template", template(EVENTS_MAPPING_WITH_ACTION))
                        .build());
        assertTrue(WCSFieldValidator.isWCSField("event.action"));
    }

    public void testKeepsFieldsWhenEventsTemplateIsRemoved() throws IOException {
        WCSFieldValidator.initFromMetadata(
                Metadata.builder().put("wazuh-events-v5-other-template", template(EVENTS_MAPPING)).build());

        WCSFieldValidator.initFromMetadata(Metadata.builder().build());

        assertTrue(WCSFieldValidator.isWCSField("event.dataset"));
        assertFalse(WCSFieldValidator.isWCSField("event.action"));
    }

    public void testPicksEventsTemplateByName() throws IOException {
        WCSFieldValidator.initFromMetadata(
                Metadata.builder()
                        .put("wazuh-events-v5-security-template", template(EVENTS_MAPPING_WITH_ACTION))
                        .put("wazuh-events-v5-applications-template", template(EVENTS_MAPPING))
                        .build());

        assertTrue(WCSFieldValidator.isWCSField("event.dataset"));
        assertFalse(WCSFieldValidator.isWCSField("event.action"));
    }

    /** A template written by a put request keeps its mapping wrapped in {@code _doc}. */
    public void testLoadsMappingWrappedInType() throws IOException {
        WCSFieldValidator.initFromMetadata(
                Metadata.builder()
                        .put(
                                "wazuh-events-v5-other-template",
                                template("{\"_doc\":" + EVENTS_MAPPING_WITH_ACTION + "}"))
                        .build());

        assertTrue(WCSFieldValidator.isWCSField("event.action"));
        assertTrue(WCSFieldValidator.isWCSField("wazuh.agent.name"));
    }

    /**
     * A composable template with its mapping as given; a template recovered from disk has it without
     * the {@code _doc} wrapper.
     */
    private static ComposableIndexTemplate template(String mapping) throws IOException {
        return new ComposableIndexTemplate(
                List.of("wazuh-events-*"),
                new Template(null, new CompressedXContent(mapping), null),
                null,
                null,
                null,
                null,
                new ComposableIndexTemplate.DataStreamTemplate());
    }

    private static IndexMetadata backingIndex(String name, String mapping) throws IOException {
        return IndexMetadata.builder(name)
                .settings(settings(Version.CURRENT))
                .numberOfShards(1)
                .numberOfReplicas(0)
                .putMapping(mapping)
                .build();
    }
}
