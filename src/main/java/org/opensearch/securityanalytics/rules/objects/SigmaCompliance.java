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

import org.opensearch.securityanalytics.rules.exceptions.SigmaError;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Compliance block for Wazuh Sigma rules. Contains a list of compliance framework entries. */
public class SigmaCompliance {

    public static final Set<String> KNOWN_FRAMEWORKS =
            new HashSet<>(
                    Arrays.asList(
                            "PCI DSS",
                            "GDPR",
                            "CMMC",
                            "NIST 800-53",
                            "NIST 800-171",
                            "HIPAA",
                            "ISO 27001",
                            "NIS2",
                            "TSC",
                            "FedRAMP"));

    private final List<ComplianceEntry> entries;

    /**
     * Constructs a SigmaCompliance instance with the provided list of compliance entries.
     *
     * @param entries a list of {@link ComplianceEntry} objects representing different compliance
     *     frameworks. If null, an empty list is assigned.
     */
    public SigmaCompliance(List<ComplianceEntry> entries) {
        this.entries = entries != null ? entries : Collections.emptyList();
    }

    /**
     * Creates a {@link SigmaCompliance} instance from a map representation of compliance frameworks.
     * Validates that each key in the map matches a known compliance framework defined in {@code
     * KNOWN_FRAMEWORKS}.
     *
     * @param map a map where keys are compliance framework names and values are their corresponding
     *     requirements.
     * @return a new {@link SigmaCompliance} instance, or null if the provided map is null.
     * @throws SigmaError if an unknown compliance framework is encountered in the map.
     */
    @SuppressWarnings("unchecked")
    public static SigmaCompliance fromMap(Map<String, Object> map) throws SigmaError {
        if (map == null) {
            return null;
        }

        List<ComplianceEntry> entries = new ArrayList<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String frameworkKey = entry.getKey();

            // Validate that the key matches a known framework (normalized)
            boolean isKnown = false;
            String originalName = frameworkKey;
            for (String knownFw : KNOWN_FRAMEWORKS) {
                if (normalizeFrameworkKey(knownFw).equals(normalizeFrameworkKey(frameworkKey))) {
                    isKnown = true;
                    originalName = knownFw;
                    break;
                }
            }

            if (!isKnown) {
                throw new SigmaError("Unknown compliance framework: '" + frameworkKey + "'.");
            }

            List<String> requirements = toStringList(entry.getValue());
            entries.add(new ComplianceEntry(originalName, requirements));
        }
        return new SigmaCompliance(entries);
    }

    /**
     * Flatten to WCS compliance format for indexing. Keys are normalized framework names, values are
     * the requirement {@code id} arrays.
     *
     * <pre>{ "pci_dss": ["11.5", ...], "gdpr": ["Article 32"] }</pre>
     *
     * @return a map representing the compliance frameworks and their requirement IDs in WCS format.
     */
    public Map<String, Object> toComplianceMap() {
        Map<String, Object> result = new HashMap<>();
        for (ComplianceEntry entry : this.entries) {
            if (entry.getName() != null && !entry.getRequirementIds().isEmpty()) {
                String key = normalizeFrameworkKey(entry.getName());
                result.put(key, new ArrayList<>(entry.getRequirementIds()));
            }
        }
        return result;
    }

    /**
     * Normalizes a compliance framework name to be used as a standardized key. Converts the string to
     * lowercase, replaces any non-alphanumeric characters with underscores, and strips leading or
     * trailing underscores.
     *
     * @param name the original framework name.
     * @return the normalized framework key string.
     */
    static String normalizeFrameworkKey(String name) {
        return name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "_").replaceAll("^_|_$", "");
    }

    /**
     * Safely converts a generic object or a list of objects into a list of strings.
     *
     * @param obj the object to convert, which can be a single object or a {@code List}.
     * @return a list of strings representing the object(s), or an empty list if the input is null.
     */
    @SuppressWarnings("unchecked")
    private static List<String> toStringList(Object obj) {
        if (obj == null) {
            return Collections.emptyList();
        }
        if (obj instanceof List) {
            List<String> result = new ArrayList<>();
            for (Object o : (List<Object>) obj) result.add(o.toString());
            return result;
        }
        return Collections.singletonList(obj.toString());
    }

    /**
     * Retrieves the list of compliance entries contained in this block.
     *
     * @return the list of {@link ComplianceEntry} objects.
     */
    public List<ComplianceEntry> getEntries() {
        return this.entries;
    }

    /** Represents a single compliance framework entry along with its associated requirement IDs. */
    public static class ComplianceEntry {
        private final String name;
        private final List<String> requirementIds;

        /**
         * Constructs a new ComplianceEntry.
         *
         * @param name the recognized name of the compliance framework (e.g., "PCI DSS").
         * @param ids a list of requirement IDs associated with the framework. If null, an empty list is
         *     assigned.
         */
        public ComplianceEntry(String name, List<String> ids) {
            this.name = name;
            this.requirementIds = ids != null ? ids : Collections.emptyList();
        }

        /**
         * Retrieves the original recognized name of the compliance framework.
         *
         * @return the compliance framework name.
         */
        public String getName() {
            return this.name;
        }

        /**
         * Retrieves the list of requirement IDs associated with this framework.
         *
         * @return the list of requirement IDs.
         */
        public List<String> getRequirementIds() {
            return this.requirementIds;
        }
    }
}
