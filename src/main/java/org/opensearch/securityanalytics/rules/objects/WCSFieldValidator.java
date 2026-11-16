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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * Validates that detection fields belong to the Wazuh Common Schema (WCS).
 *
 * <p>WCS fields are resolved from the mapping of the events index template, and refreshed whenever
 * that mapping changes, via {@link #initFromMetadata(Metadata)}.
 *
 * <p>If the validator has not been initialized (no index mapping available yet), all fields are
 * accepted to avoid blocking rule ingestion during cluster bootstrap.
 */
public class WCSFieldValidator {

    private static final Logger log = LogManager.getLogger(WCSFieldValidator.class);

    /**
     * Name prefix of the events index templates: the setup plugin installs one {@code
     * wazuh-events-v5-<category>-template} per category, all with the same mapping. The raw events
     * template ({@code wazuh-events-raw-v5-template}) does not match it.
     */
    private static final String EVENTS_TEMPLATE_PREFIX = "wazuh-events-v5-";

    /** WCS fields resolved from the index mapping. */
    private static final AtomicReference<Set<String>> wcsFields =
            new AtomicReference<>(Collections.emptySet());

    /**
     * Mapping of the last load attempt, so an unchanged template is neither reparsed nor, if it
     * cannot be parsed, reported again.
     */
    private static final AtomicReference<CompressedXContent> loadedMapping = new AtomicReference<>();

    /**
     * Initialize (or refresh) the WCS field set from the events index template in the cluster
     * metadata. Called on every cluster metadata change; it does nothing when no events template
     * exists yet or when its mapping is the one already loaded.
     *
     * @param metadata the cluster metadata
     */
    public static void initFromMetadata(Metadata metadata) {
        try {
            metadata.templatesV2().entrySet().stream()
                    .filter(e -> e.getKey().startsWith(EVENTS_TEMPLATE_PREFIX))
                    .filter(e -> e.getValue().template() != null)
                    .filter(e -> e.getValue().template().mappings() != null)
                    // the templates share one mapping: pick by name so the choice never varies
                    .min(Map.Entry.comparingByKey())
                    .ifPresent(e -> initFromMapping(e.getKey(), e.getValue().template().mappings()));
        } catch (Exception e) {
            log.warn("Failed to initialize WCS field validator from cluster state", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static void initFromMapping(String templateName, CompressedXContent mapping) {
        if (mapping.equals(loadedMapping.getAndSet(mapping))) {
            return;
        }

        Set<String> fields = new HashSet<>();
        Map<String, Object> sourceMap =
                XContentHelper.convertToMap(mapping.compressedReference(), true, MediaTypeRegistry.JSON)
                        .v2();
        // A template mapping may be stored wrapped in its type
        if (sourceMap.size() == 1
                && sourceMap.get(MapperService.SINGLE_MAPPING_NAME) instanceof Map<?, ?> typed) {
            sourceMap = (Map<String, Object>) typed;
        }

        // Extract from dynamic_templates
        Object dynTemplates = sourceMap.get("dynamic_templates");
        if (dynTemplates instanceof List) {
            for (Object tplObj : (List<?>) dynTemplates) {
                if (tplObj instanceof Map) {
                    for (Object tplBody : ((Map<?, ?>) tplObj).values()) {
                        if (tplBody instanceof Map) {
                            Object pathMatch = ((Map<?, ?>) tplBody).get("path_match");
                            if (pathMatch instanceof String && !((String) pathMatch).isEmpty()) {
                                fields.add((String) pathMatch);
                            }
                        }
                    }
                }
            }
        }

        // Extract from properties (recursive)
        Object properties = sourceMap.get("properties");
        if (properties instanceof Map) {
            extractProperties((Map<?, ?>) properties, "", fields);
        }

        wcsFields.set(Collections.unmodifiableSet(fields));

        log.info(
                "WCS field validator initialized with {} fields from index template [{}]",
                fields.size(),
                templateName);
    }

    /**
     * Initialize from a raw set of field names (for testing or manual override).
     *
     * @param fields the set of field names to use as the valid WCS fields
     */
    public static void initFromFieldSet(Set<String> fields) {
        wcsFields.set(Collections.unmodifiableSet(new HashSet<>(fields)));
        loadedMapping.set(null);
    }

    /** Reset the validator to uninitialized state (for testing). */
    public static void reset() {
        wcsFields.set(Collections.emptySet());
        loadedMapping.set(null);
    }

    /**
     * Checks whether the validator has been initialized with WCS fields.
     *
     * @return true if the validator has been initialized with WCS fields.
     */
    public static boolean isInitialized() {
        return !wcsFields.get().isEmpty();
    }

    /**
     * Validate that all fields in the detection stanza are WCS fields.
     *
     * @param detectionMap the raw detection map from the YAML
     * @return list of unknown field names (empty if all valid)
     */
    public static List<String> findUnknownFields(Map<String, Object> detectionMap) {
        Set<String> referencedFields = new HashSet<>();
        extractFields(detectionMap, referencedFields);

        return referencedFields.stream()
                .filter(f -> !isWCSField(f))
                .sorted()
                .collect(Collectors.toList());
    }

    /**
     * Checks if a specific field name is recognized as a valid WCS field. If the validator is not
     * initialized, all fields are considered valid.
     *
     * @param field the field name to check
     * @return true if the field is in the WCS set, or if the validator is uninitialized
     */
    public static boolean isWCSField(String field) {
        if (field == null || field.isEmpty() || !isInitialized()) {
            return true;
        }

        return wcsFields.get().contains(field);
    }

    /**
     * Recursively extracts field names from a nested detection map. Ignores specific keys like
     * "condition" and "timeframe".
     *
     * @param map the map to extract fields from
     * @param fields the set to add found fields to
     */
    @SuppressWarnings("unchecked")
    private static void extractFields(Map<String, Object> map, Set<String> fields) {
        if (map == null) {
            return;
        }
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            if ("condition".equals(key) || "timeframe".equals(key)) {
                continue;
            }

            Object val = entry.getValue();
            if (val instanceof Map) {
                Map<String, Object> inner = (Map<String, Object>) val;
                for (String innerKey : inner.keySet()) {
                    if ("condition".equals(innerKey) || "timeframe".equals(innerKey)) {
                        continue;
                    }
                    String fieldName =
                            innerKey.contains("|") ? innerKey.substring(0, innerKey.indexOf('|')) : innerKey;
                    if (!fieldName.isEmpty()) {
                        fields.add(fieldName);
                    }
                }
            } else if (val instanceof List) {
                for (Object item : (List<Object>) val) {
                    if (item instanceof Map) {
                        extractFields(Collections.singletonMap(key, item), fields);
                    }
                }
            }
        }
    }

    /**
     * Recursively extracts property field paths from an index mapping property definition.
     *
     * @param properties the properties map from the mapping
     * @param prefix the current field path prefix
     * @param fields the set to add the full field paths to
     */
    @SuppressWarnings("unchecked")
    private static void extractProperties(Map<?, ?> properties, String prefix, Set<String> fields) {
        for (Map.Entry<?, ?> entry : properties.entrySet()) {
            String key = entry.getKey().toString();
            String fullPath = prefix.isEmpty() ? key : prefix + "." + key;
            Object value = entry.getValue();
            if (value instanceof Map) {
                Map<?, ?> propDef = (Map<?, ?>) value;
                if (propDef.containsKey("properties")) {
                    Object nested = propDef.get("properties");
                    if (nested instanceof Map) {
                        extractProperties((Map<?, ?>) nested, fullPath, fields);
                    }
                } else {
                    fields.add(fullPath);
                }
            }
        }
    }

    /**
     * Validate detection fields and throw if unknown fields found.
     *
     * @param detectionMap the raw detection map from the YAML
     * @throws SigmaError if unknown WCS fields are found in the detection map
     */
    public static void validateDetectionFields(Map<String, Object> detectionMap) throws SigmaError {
        if (detectionMap == null) {
            return;
        }
        List<String> unknownFields = findUnknownFields(detectionMap);
        if (!unknownFields.isEmpty()) {
            throw new SigmaError(
                    "The following fields are not part of the Wazuh Common Schema (WCS): " + unknownFields);
        }
    }

    /** Private constructor to prevent instantiation of this utility class. */
    private WCSFieldValidator() {}
}
