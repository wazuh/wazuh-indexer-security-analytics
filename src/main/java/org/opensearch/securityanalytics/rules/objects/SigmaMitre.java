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

    public SigmaMitre(List<String> tactic, List<String> technique, List<String> subtechnique) {
        this.tactic = tactic != null ? tactic : Collections.emptyList();
        this.technique = technique != null ? technique : Collections.emptyList();
        this.subtechnique = subtechnique != null ? subtechnique : Collections.emptyList();
    }

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
     * Flatten to WCS MITRE format for indexing.
     * Subtechnique IDs are also merged into the technique array per the WCS spec.
     */
    public Map<String, Object> toMitreMap() {
        Map<String, Object> mitreMap = new HashMap<>();
        if (!tactic.isEmpty()) {
            mitreMap.put("tactic", new ArrayList<>(tactic));
        }

        List<String> allTechniques = new ArrayList<>(technique);
        allTechniques.addAll(subtechnique);
        if (!allTechniques.isEmpty()) {
            mitreMap.put("technique", allTechniques);
        }

        if (!subtechnique.isEmpty()) {
            mitreMap.put("subtechnique", new ArrayList<>(subtechnique));
        }
        return mitreMap;
    }

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

    public List<String> getTactic() {
        return tactic;
    }

    public List<String> getTechnique() {
        return technique;
    }

    public List<String> getSubtechnique() {
        return subtechnique;
    }
}
