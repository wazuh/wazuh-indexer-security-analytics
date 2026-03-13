/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Validates that detection fields belong to the Wazuh Common Schema (WCS).
 * <p>
 * WCS fields are resolved dynamically from the OpenSearch index mapping at plugin
 * startup (or on cluster state changes) via {@link #initFromIndexMetadata(IndexMetadata)}.
 * A supplementary set of Sigma-native field names (e.g. Windows Sysmon conventions) is
 * loaded from a bundled resource file.
 * <p>
 * If the validator has not been initialized (no index mapping available yet), all fields
 * are accepted to avoid blocking rule ingestion during cluster bootstrap.
 */
public class WCSFieldValidator {

    private static final Logger log = Logger.getLogger(WCSFieldValidator.class.getName());

    /** WCS fields resolved from the index mapping. */
    private static final AtomicReference<Set<String>> wcsFields = new AtomicReference<>(Collections.emptySet());

    /**
     * Initialize (or refresh) the WCS field set from an OpenSearch index metadata mapping.
     * Typically called once at plugin startup and optionally on cluster state changes.
     *
     * @param indexMetadata metadata for any {@code wazuh-events-*} index (all share the same mapping)
     */
    public static void initFromIndexMetadata(IndexMetadata indexMetadata) {
        if (indexMetadata == null) {
            log.warning("Cannot initialize WCS fields: null index metadata");
            return;
        }

        MappingMetadata mapping = indexMetadata.mapping();
        if (mapping == null) {
            log.warning("Cannot initialize WCS fields: no mapping in index metadata");
            return;
        }

        Set<String> fields = new HashSet<>();
        Map<String, Object> sourceMap = mapping.sourceAsMap();

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

        log.info("WCS field validator initialized with " + fields.size() + " fields");
    }

    /**
     * Initialize from a raw set of field names (for testing or manual override).
     */
    public static void initFromFieldSet(Set<String> fields) {
        wcsFields.set(Collections.unmodifiableSet(new HashSet<>(fields)));
    }

    /**
     * Reset the validator to uninitialized state (for testing).
     */
    public static void reset() {
        wcsFields.set(Collections.emptySet());
    }

    /**
     * @return true if the validator has been initialized with WCS fields.
     */
    public static boolean isInitialized() {
        return !wcsFields.get().isEmpty();
    }

    /**
     * Validate that all fields in the detection stanza are WCS fields.
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

    public static boolean isWCSField(String field) {
        if (field == null || field.isEmpty()){
            return true;
        }

        return wcsFields.get().contains(field);
    }

    @SuppressWarnings("unchecked")
    private static void extractFields(Map<String, Object> map, Set<String> fields) {
        if (map == null) {
            return;
        }
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            if ("condition".equals(key) || "timeframe".equals(key)){
                continue;
            }

            Object val = entry.getValue();
            if (val instanceof Map) {
                Map<String, Object> inner = (Map<String, Object>) val;
                for (String innerKey : inner.keySet()) {
                    if ("condition".equals(innerKey) || "timeframe".equals(innerKey)){
                        continue;
                    }
                    String fieldName = innerKey.contains("|") ? innerKey.substring(0, innerKey.indexOf('|')) : innerKey;
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
     */
    public static void validateDetectionFields(Map<String, Object> detectionMap) throws SigmaError {
        if (detectionMap == null){
            return;
        }
        List<String> unknownFields = findUnknownFields(detectionMap);
        if (!unknownFields.isEmpty()) {
            throw new SigmaError("Unknown WCS fields in detection: " + unknownFields);
        }
    }

    /**
     * Load a set of strings from a classpath resource (one entry per line).
     * Blank lines and lines starting with {@code #} are ignored.
     */
    private static Set<String> loadLineSet(String resource) {
        Set<String> result = new HashSet<>();
        try (InputStream is = WCSFieldValidator.class.getClassLoader().getResourceAsStream(resource)) {
            if (is == null) {
                log.warning("Resource not found: " + resource);
                return result;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        result.add(line);
                    }
                }
            }
        } catch (IOException e) {
            log.log(Level.WARNING, "Failed to load " + resource, e);
        }
        return result;
    }

    private WCSFieldValidator() {}
}
