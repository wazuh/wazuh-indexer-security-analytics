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
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
 *
 * <p>A deprecated shorthand in which each category is a plain array of ID strings is also accepted,
 * and is equivalent to supplying only {@code id}:
 *
 * <pre>{@code
 * mitre:
 *   tactic:
 *     - TA0003
 *   technique:
 *     - T1098
 * }</pre>
 *
 * <p>This shorthand was the documented format before the {@code id}/{@code name} structure was
 * introduced. It is parsed for backwards compatibility with rules authored against those docs, but
 * it cannot carry ATT&amp;CK names, so {@code tactic.name}, {@code technique.name} and {@code
 * subtechnique.name} are left empty. New rules should use the nested form.
 *
 * <p>A {@code mitre} block that cannot be interpreted as either form raises a {@link SigmaError}
 * rather than being silently discarded.
 */
public class SigmaMitre {

    private static final Logger log = LogManager.getLogger(SigmaMitre.class);

    /** Recognized MITRE category keys within the {@code mitre} block. */
    private static final Set<String> CATEGORIES = Set.of("tactic", "technique", "subtechnique");

    /** Recognized keys within a single nested MITRE category. */
    private static final Set<String> CATEGORY_KEYS = Set.of("id", "name");

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
     * <p>Each category may be supplied either as an object with {@code id} and {@code name} arrays
     * (the current format) or as a plain array of ID strings (the deprecated shorthand). Any other
     * structure, or an unrecognized key, is reported as an error instead of being ignored.
     *
     * @param map the map containing 'tactic', 'technique', and 'subtechnique' keys
     * @return a new SigmaMitre instance, or null if the input map is null
     * @throws SigmaError if the block contains unrecognized keys or malformed categories
     */
    public static SigmaMitre fromDict(Map<String, Object> map) throws SigmaError {
        if (map == null) {
            return null;
        }

        List<String> problems = new ArrayList<>();
        Set<String> legacyCategories = new LinkedHashSet<>();

        for (Object key : map.keySet()) {
            String name = String.valueOf(key);
            if (!CATEGORIES.contains(name)) {
                problems.add(
                        "'mitre."
                                + name
                                + "' is not a supported MITRE category; expected one of "
                                + CATEGORIES);
            }
        }

        Category tactic = parseCategory("tactic", map.get("tactic"), problems, legacyCategories);
        Category technique =
                parseCategory("technique", map.get("technique"), problems, legacyCategories);
        Category subtechnique =
                parseCategory("subtechnique", map.get("subtechnique"), problems, legacyCategories);

        if (!problems.isEmpty()) {
            throw new SigmaError("Invalid 'mitre' block: " + String.join("; ", problems));
        }

        if (!legacyCategories.isEmpty()) {
            log.warn(
                    "Rule uses the deprecated MITRE shorthand (plain ID arrays) for {}. ATT&CK names "
                            + "cannot be derived from IDs, so 'name' will be empty for those categories. "
                            + "Use the nested form instead, e.g. 'mitre.tactic.id' and 'mitre.tactic.name'.",
                    legacyCategories);
        }

        return new SigmaMitre(
                tactic.ids,
                tactic.names,
                technique.ids,
                technique.names,
                subtechnique.ids,
                subtechnique.names);
    }

    /** The {@code id} and {@code name} values parsed from a single MITRE category. */
    private static final class Category {

        private static final Category EMPTY =
                new Category(Collections.emptyList(), Collections.emptyList());

        private final List<String> ids;
        private final List<String> names;

        private Category(List<String> ids, List<String> names) {
            this.ids = ids;
            this.names = names;
        }
    }

    /**
     * Parses a single MITRE category, accepting both the nested {@code id}/{@code name} object and
     * the deprecated plain array of ID strings.
     *
     * @param category the category name, used for error messages
     * @param value the raw value for the category, may be {@code null}
     * @param problems accumulator for validation problems found while parsing
     * @param legacyCategories accumulator for categories supplied in the deprecated shorthand
     * @return the parsed IDs and names, never {@code null}
     */
    private static Category parseCategory(
            String category, Object value, List<String> problems, Set<String> legacyCategories) {
        if (value == null) {
            return Category.EMPTY;
        }

        if (value instanceof Map) {
            Map<?, ?> categoryMap = (Map<?, ?>) value;
            List<String> unsupported = new ArrayList<>();
            for (Object key : categoryMap.keySet()) {
                String name = String.valueOf(key);
                if (!CATEGORY_KEYS.contains(name)) {
                    unsupported.add(name);
                }
            }
            if (!unsupported.isEmpty()) {
                problems.add(
                        "'mitre."
                                + category
                                + "' contains unsupported key(s) "
                                + unsupported
                                + "; expected 'id' and/or 'name'");
                return Category.EMPTY;
            }
            return new Category(
                    toStringList(categoryMap.get("id")), toStringList(categoryMap.get("name")));
        }

        if (value instanceof List) {
            List<String> ids = toStringList(value);
            if (!ids.isEmpty()) {
                legacyCategories.add(category);
            }
            return new Category(ids, Collections.emptyList());
        }

        if (value instanceof String || value instanceof Number || value instanceof Boolean) {
            legacyCategories.add(category);
            return new Category(toStringList(value), Collections.emptyList());
        }

        problems.add(
                "'mitre."
                        + category
                        + "' must be an array of ID strings or an object with 'id'/'name' arrays, but"
                        + " was "
                        + value.getClass().getSimpleName());
        return Category.EMPTY;
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
