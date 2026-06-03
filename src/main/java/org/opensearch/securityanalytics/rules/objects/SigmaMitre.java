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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MITRE ATT&amp;CK block for Wazuh Sigma rules.
 *
 * <p>Parses a top-level {@code mitre} structure where each category ({@code tactic}, {@code
 * technique}, {@code subtechnique}) is an object containing {@code id} and {@code name} arrays.
 *
 * <pre>{@code
 * mitre:
 *   tactic:
 *     id:
 *       - TA0003
 *     name:
 *       - Persistence
 *   technique:
 *     id:
 *       - T1098
 *     name:
 *       - Account Manipulation
 * }</pre>
 */
public class SigmaMitre {

    private final List<String> tacticId;
    private final List<String> tacticName;
    private final List<String> techniqueId;
    private final List<String> techniqueName;
    private final List<String> subtechniqueId;
    private final List<String> subtechniqueName;

    /**
     * Constructs a new SigmaMitre instance.
     *
     * @param tacticId list of MITRE tactic IDs; if null, an empty list is used
     * @param tacticName list of MITRE tactic names; if null, an empty list is used
     * @param techniqueId list of MITRE technique IDs; if null, an empty list is used
     * @param techniqueName list of MITRE technique names; if null, an empty list is used
     * @param subtechniqueId list of MITRE sub-technique IDs; if null, an empty list is used
     * @param subtechniqueName list of MITRE sub-technique names; if null, an empty list is used
     */
    public SigmaMitre(
            List<String> tacticId,
            List<String> tacticName,
            List<String> techniqueId,
            List<String> techniqueName,
            List<String> subtechniqueId,
            List<String> subtechniqueName) {
        this.tacticId = tacticId != null ? tacticId : Collections.emptyList();
        this.tacticName = tacticName != null ? tacticName : Collections.emptyList();
        this.techniqueId = techniqueId != null ? techniqueId : Collections.emptyList();
        this.techniqueName = techniqueName != null ? techniqueName : Collections.emptyList();
        this.subtechniqueId = subtechniqueId != null ? subtechniqueId : Collections.emptyList();
        this.subtechniqueName = subtechniqueName != null ? subtechniqueName : Collections.emptyList();
    }

    /**
     * Creates a {@link SigmaMitre} instance from a dictionary/map representation. Each category
     * ({@code tactic}, {@code technique}, {@code subtechnique}) is expected to be an object with
     * {@code id} and {@code name} array fields.
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

        List<String> tacticId = Collections.emptyList();
        List<String> tacticName = Collections.emptyList();
        List<String> techniqueId = Collections.emptyList();
        List<String> techniqueName = Collections.emptyList();
        List<String> subtechniqueId = Collections.emptyList();
        List<String> subtechniqueName = Collections.emptyList();

        Object tacticObj = map.get("tactic");
        if (tacticObj instanceof Map) {
            Map<String, Object> tacticMap = (Map<String, Object>) tacticObj;
            tacticId = toStringList(tacticMap.get("id"));
            tacticName = toStringList(tacticMap.get("name"));
        }

        Object techniqueObj = map.get("technique");
        if (techniqueObj instanceof Map) {
            Map<String, Object> techniqueMap = (Map<String, Object>) techniqueObj;
            techniqueId = toStringList(techniqueMap.get("id"));
            techniqueName = toStringList(techniqueMap.get("name"));
        }

        Object subtechniqueObj = map.get("subtechnique");
        if (subtechniqueObj instanceof Map) {
            Map<String, Object> subtechniqueMap = (Map<String, Object>) subtechniqueObj;
            subtechniqueId = toStringList(subtechniqueMap.get("id"));
            subtechniqueName = toStringList(subtechniqueMap.get("name"));
        }

        return new SigmaMitre(
                tacticId, tacticName, techniqueId, techniqueName, subtechniqueId, subtechniqueName);
    }

    /**
     * Builds the MITRE data into the nested format for WCS indexing. Per the WCS spec, sub-technique
     * IDs and names are merged into the technique arrays.
     *
     * @return a map representing the nested MITRE ATT&amp;CK data
     */
    public Map<String, Object> toMitreMap() {
        Map<String, Object> mitreMap = new HashMap<>();

        if (!this.tacticId.isEmpty() || !this.tacticName.isEmpty()) {
            Map<String, Object> tacticMap = new HashMap<>();
            if (!this.tacticId.isEmpty()) {
                tacticMap.put("id", new ArrayList<>(this.tacticId));
            }
            if (!this.tacticName.isEmpty()) {
                tacticMap.put("name", new ArrayList<>(this.tacticName));
            }
            mitreMap.put("tactic", tacticMap);
        }

        List<String> allTechniqueIds = new ArrayList<>(this.techniqueId);
        allTechniqueIds.addAll(this.subtechniqueId);
        List<String> allTechniqueNames = new ArrayList<>(this.techniqueName);
        allTechniqueNames.addAll(this.subtechniqueName);
        if (!allTechniqueIds.isEmpty() || !allTechniqueNames.isEmpty()) {
            Map<String, Object> techniqueMap = new HashMap<>();
            if (!allTechniqueIds.isEmpty()) {
                techniqueMap.put("id", allTechniqueIds);
            }
            if (!allTechniqueNames.isEmpty()) {
                techniqueMap.put("name", allTechniqueNames);
            }
            mitreMap.put("technique", techniqueMap);
        }

        if (!this.subtechniqueId.isEmpty() || !this.subtechniqueName.isEmpty()) {
            Map<String, Object> subtechniqueMap = new HashMap<>();
            if (!this.subtechniqueId.isEmpty()) {
                subtechniqueMap.put("id", new ArrayList<>(this.subtechniqueId));
            }
            if (!this.subtechniqueName.isEmpty()) {
                subtechniqueMap.put("name", new ArrayList<>(this.subtechniqueName));
            }
            mitreMap.put("subtechnique", subtechniqueMap);
        }

        return mitreMap;
    }

    /**
     * Utility method to convert an object (which could be a single String or a List) into a List of
     * Strings.
     *
     * @param obj the object to convert
     * @return a list of strings representation of the input object
     */
    @SuppressWarnings("unchecked")
    private static List<String> toStringList(Object obj) {
        if (obj == null) {
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
     * @return the list of tactic IDs
     */
    public List<String> getTacticId() {
        return this.tacticId;
    }

    /**
     * @return the list of tactic names
     */
    public List<String> getTacticName() {
        return this.tacticName;
    }

    /**
     * @return the list of technique IDs
     */
    public List<String> getTechniqueId() {
        return this.techniqueId;
    }

    /**
     * @return the list of technique names
     */
    public List<String> getTechniqueName() {
        return this.techniqueName;
    }

    /**
     * @return the list of sub-technique IDs
     */
    public List<String> getSubtechniqueId() {
        return this.subtechniqueId;
    }

    /**
     * @return the list of sub-technique names
     */
    public List<String> getSubtechniqueName() {
        return this.subtechniqueName;
    }
}
