/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
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

/**
 * Compliance block for Wazuh Sigma rules. Contains a list of compliance framework entries.
 */
public class SigmaCompliance {

    public static final Set<String> KNOWN_FRAMEWORKS = new HashSet<>(Arrays.asList(
            "PCI DSS", "GDPR", "CMMC", "NIST 800-53", "NIST 800-171",
            "HIPAA", "ISO 27001", "NIS2", "TSC", "FedRAMP"
    ));

    private final List<ComplianceEntry> entries;

    public SigmaCompliance(List<ComplianceEntry> entries) {
        this.entries = entries != null ? entries : Collections.emptyList();
    }

    @SuppressWarnings("unchecked")
    public static SigmaCompliance fromMap(Map<String, Object> map) throws SigmaError {
        if (map == null){
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
     * Flatten to WCS compliance format for indexing.
     * Keys are normalized framework names, values are the requirement {@code id} arrays.
     * <pre>{ "pci_dss": ["11.5", ...], "gdpr": ["Article 32"] }</pre>
     */
    public Map<String, Object> toComplianceMap() {
        Map<String, Object> result = new HashMap<>();
        for (ComplianceEntry entry : entries) {
            if (entry.getName() != null && !entry.getRequirementIds().isEmpty()) {
                String key = normalizeFrameworkKey(entry.getName());
                result.put(key, new ArrayList<>(entry.getRequirementIds()));
            }
        }
        return result;
    }

    static String normalizeFrameworkKey(String name) {
        return name.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "_")
                .replaceAll("^_|_$", "");
    }

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

    public List<ComplianceEntry> getEntries() { return entries; }

    public static class ComplianceEntry {
        private final String name;
        private final List<String> requirementIds;

        public ComplianceEntry(String name, List<String> ids) {
            this.name = name;
            this.requirementIds = ids != null ? ids : Collections.emptyList();
        }

        public String getName() {
            return name;
        }
        public List<String> getRequirementIds() {
            return requirementIds;
        }
    }
}
