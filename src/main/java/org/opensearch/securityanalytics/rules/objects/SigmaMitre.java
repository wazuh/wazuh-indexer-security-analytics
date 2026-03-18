/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.securityanalytics.rules.exceptions.SigmaError;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MITRE ATT&amp;CK block for Wazuh Sigma rules.
 * <p>
 * Parses a top-level {@code mitre} structure containing flat arrays
 * for {@code tactic}, {@code technique}, and {@code subtechnique}.
 */
public class SigmaMitre {

    private final List<String> tactic;
    private final List<String> technique;
    private final List<String> subtechnique;

    /**
     * Constructs a new SigmaMitre instance with specified tactics, techniques, and sub-techniques.
     *
     * @param tactic a list of MITRE tactics; if null, an empty list is used
     * @param technique a list of MITRE techniques; if null, an empty list is used
     * @param subtechnique a list of MITRE sub-techniques; if null, an empty list is used
     */
    public SigmaMitre(List<String> tactic, List<String> technique, List<String> subtechnique) {
        this.tactic = tactic != null ? tactic : Collections.emptyList();
        this.technique = technique != null ? technique : Collections.emptyList();
        this.subtechnique = subtechnique != null ? subtechnique : Collections.emptyList();
    }

    /**
     * Creates a {@link SigmaMitre} instance from a dictionary/map representation.
     *
     * @param map the map containing 'tactic', 'technique', and 'subtechnique' keys
     * @return a new SigmaMitre instance, or null if the input map is null
     * @throws SigmaError if there is an error during parsing
     */
    @SuppressWarnings("unchecked")
    public static SigmaMitre fromDict(Map<String, Object> map) throws SigmaError {
        if (map == null) {
            return null;
        }

        List<String> tactic = toStringList(map.get("tactic"));
        List<String> technique = toStringList(map.get("technique"));
        List<String> subtechnique = toStringList(map.get("subtechnique"));

        return new SigmaMitre(tactic, technique, subtechnique);
    }

    /**
     * Flattens the MITRE data into a format suitable for WCS indexing.
     * Per the WCS spec, sub-technique IDs are merged into the technique array.
     *
     * @return a map representing the flattened MITRE ATT&amp;CK data
     */
    public Map<String, Object> toMitreMap() {
        Map<String, Object> mitreMap = new HashMap<>();
        if (!this.tactic.isEmpty()) {
            mitreMap.put("tactic", new ArrayList<>(this.tactic));
        }

        List<String> allTechniques = new ArrayList<>(this.technique);
        allTechniques.addAll(this.subtechnique);
        if (!allTechniques.isEmpty()) {
            mitreMap.put("technique", allTechniques);
        }

        if (!this.subtechnique.isEmpty()) {
            mitreMap.put("subtechnique", new ArrayList<>(this.subtechnique));
        }
        return mitreMap;
    }

    /**
     * Utility method to convert an object (which could be a single String or a List) into a List of Strings.
     *
     * @param obj the object to convert
     * @return a list of strings representation of the input object
     */
    @SuppressWarnings("unchecked")
    private static List<String> toStringList(Object obj) {
        if (obj == null){
            return Collections.emptyList();
        }
        if (obj instanceof List) {
            List<String> result = new ArrayList<>();
            for (Object o : (List<Object>) obj) {
                result.add(o.toString());
            }
            return result;
        }
        return Collections.singletonList(obj.toString());
    }

    /**
     * @return the list of tactics
     */
    public List<String> getTactic() {
        return this.tactic;
    }

    /**
     * @return the list of techniques
     */
    public List<String> getTechnique() {
        return this.technique;
    }

    /**
     * @return the list of sub-techniques
     */
    public List<String> getSubtechnique() {
        return this.subtechnique;
    }
}
