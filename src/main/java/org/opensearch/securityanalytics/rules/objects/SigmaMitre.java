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
 * <p>Each category may equivalently be given as an array holding one {@code id}/{@code name} object
 * per ATT&amp;CK entry, which pairs each ID with its name directly:
 *
 * <pre>{@code
 * mitre:
 *   tactic:
 *     - id: TA0003
 *       name: Persistence
 *   technique:
 *     - id: T1098
 *       name: Account Manipulation
 * }</pre>
 *
 * <p>Because the parsed IDs and names are held as parallel arrays, {@code name} must be supplied
 * for every entry of a category or for none of them.
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
 * subtechnique.name} are left empty. New rules should use one of the two named forms.
 *
 * <p>A {@code mitre} block that cannot be interpreted as one of these forms raises a {@link
 * SigmaError} rather than being silently discarded.
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
     * <p>Each category may be supplied as an object with {@code id} and {@code name} arrays, as an
     * array of per-entry {@code id}/{@code name} objects, or as a plain array of ID strings (the
     * deprecated shorthand). Any other structure, or an unrecognized key, is reported as an error
     * instead of being ignored.
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
     * Parses a single MITRE category, accepting the parallel {@code id}/{@code name} arrays, an array
     * of per-entry {@code id}/{@code name} objects, and the deprecated plain array of ID strings.
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
            List<String> unsupported = unsupportedKeys(categoryMap);
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
                    toStringList("mitre." + category + ".id", categoryMap.get("id"), problems),
                    toStringList("mitre." + category + ".name", categoryMap.get("name"), problems));
        }

        if (value instanceof List) {
            return parseCategoryArray(category, (List<?>) value, problems, legacyCategories);
        }

        if (isScalar(value)) {
            legacyCategories.add(category);
            return new Category(
                    toStringList("mitre." + category, value, problems), Collections.emptyList());
        }

        problems.add(
                "'mitre."
                        + category
                        + "' must be an array or an object with 'id'/'name' arrays, but was "
                        + describe(value));
        return Category.EMPTY;
    }

    /**
     * Parses a MITRE category supplied as an array. The elements are either plain ID strings (the
     * deprecated shorthand) or one {@code id}/{@code name} object per ATT&amp;CK entry. The two
     * element kinds may not be mixed within a single array.
     *
     * @param category the category name, used for error messages
     * @param values the array elements, never {@code null}
     * @param problems accumulator for validation problems found while parsing
     * @param legacyCategories accumulator for categories supplied in the deprecated shorthand
     * @return the parsed IDs and names, never {@code null}
     */
    private static Category parseCategoryArray(
            String category, List<?> values, List<String> problems, Set<String> legacyCategories) {
        if (values.isEmpty()) {
            return Category.EMPTY;
        }

        boolean hasEntries = false;
        boolean hasIds = false;
        for (Object element : values) {
            if (element instanceof Map) {
                hasEntries = true;
            } else if (isScalar(element)) {
                hasIds = true;
            } else {
                problems.add(
                        "'mitre."
                                + category
                                + "' contains an element of type "
                                + describe(element)
                                + "; expected an ID string or an object with 'id'/'name'");
                return Category.EMPTY;
            }
        }

        if (hasEntries && hasIds) {
            problems.add(
                    "'mitre."
                            + category
                            + "' mixes ID strings with 'id'/'name' objects; use a single form for the"
                            + " whole array");
            return Category.EMPTY;
        }

        if (!hasEntries) {
            legacyCategories.add(category);
            return new Category(
                    toStringList("mitre." + category, values, problems), Collections.emptyList());
        }

        return parseCategoryEntries(category, values, problems);
    }

    /**
     * Flattens one {@code id}/{@code name} object per ATT&amp;CK entry into the parallel ID and name
     * arrays the WCS mapping expects.
     *
     * <p>Every entry must carry an {@code id}. Because the target arrays are positional, {@code name}
     * must be supplied for every entry or for none — a partially named array would leave the IDs and
     * names misaligned, so it is reported as an error.
     *
     * @param category the category name, used for error messages
     * @param values the array elements, each already known to be a {@link Map}
     * @param problems accumulator for validation problems found while parsing
     * @return the parsed IDs and names, never {@code null}
     */
    private static Category parseCategoryEntries(
            String category, List<?> values, List<String> problems) {
        List<String> ids = new ArrayList<>(values.size());
        List<String> names = new ArrayList<>(values.size());
        int unnamed = 0;

        for (int i = 0; i < values.size(); i++) {
            Map<?, ?> entry = (Map<?, ?>) values.get(i);
            String location = "mitre." + category + "[" + i + "]";

            List<String> unsupported = unsupportedKeys(entry);
            if (!unsupported.isEmpty()) {
                problems.add(
                        "'"
                                + location
                                + "' contains unsupported key(s) "
                                + unsupported
                                + "; expected 'id' and/or 'name'");
                continue;
            }

            Object idValue = entry.get("id");
            if (idValue == null) {
                problems.add("'" + location + "' is missing 'id'");
                continue;
            }
            String id = scalarValue(location + ".id", idValue, problems);
            if (id == null) {
                continue;
            }
            ids.add(id);

            Object nameValue = entry.get("name");
            if (nameValue == null) {
                unnamed++;
                continue;
            }
            String name = scalarValue(location + ".name", nameValue, problems);
            if (name != null) {
                names.add(name);
            }
        }

        if (unnamed > 0 && !names.isEmpty()) {
            problems.add(
                    "'mitre."
                            + category
                            + "' supplies 'name' for only some entries; the ID and name arrays are"
                            + " positional, so 'name' must be given for every entry or for none");
            return Category.EMPTY;
        }

        return new Category(ids, names);
    }

    /**
     * Collects the keys of a MITRE category or entry object that are neither {@code id} nor {@code
     * name}.
     *
     * @param map the object to inspect
     * @return the unsupported keys, empty if all keys are recognized
     */
    private static List<String> unsupportedKeys(Map<?, ?> map) {
        List<String> unsupported = new ArrayList<>();
        for (Object key : map.keySet()) {
            String name = String.valueOf(key);
            if (!CATEGORY_KEYS.contains(name)) {
                unsupported.add(name);
            }
        }
        return unsupported;
    }

    /**
     * Whether a parsed YAML value is a scalar, and therefore safe to render as a string.
     *
     * @param value the value to test, may be {@code null}
     * @return true if the value is a string, number or boolean
     */
    private static boolean isScalar(Object value) {
        return value instanceof String || value instanceof Number || value instanceof Boolean;
    }

    /**
     * Renders a scalar value as a string, reporting a problem when the value is a collection. This
     * prevents a nested structure from being silently stringified into a bogus ID or name.
     *
     * @param location the dotted path of the value, used for error messages
     * @param value the value to render
     * @param problems accumulator for validation problems found while parsing
     * @return the string form of the value, or {@code null} if it was not a scalar
     */
    private static String scalarValue(String location, Object value, List<String> problems) {
        if (isScalar(value)) {
            return value.toString();
        }
        problems.add("'" + location + "' must be a single value, but was " + describe(value));
        return null;
    }

    /**
     * Names the type of an unexpected value for use in error messages.
     *
     * @param value the value to describe, may be {@code null}
     * @return the simple class name, or {@code "null"}
     */
    private static String describe(Object value) {
        return value == null ? "null" : value.getClass().getSimpleName();
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
     * Converts a value that may be either a single scalar or an array of scalars into a list of
     * strings. Non-scalar elements are reported as problems and dropped rather than being rendered
     * via {@link Object#toString()}, which would yield a bogus ID or name.
     *
     * @param location the dotted path of the value, used for error messages
     * @param value the value to convert, may be {@code null}
     * @param problems accumulator for validation problems found while parsing
     * @return the string values, never {@code null}
     */
    private static List<String> toStringList(String location, Object value, List<String> problems) {
        if (value == null) {
            return Collections.emptyList();
        }
        if (value instanceof List) {
            List<?> values = (List<?>) value;
            List<String> result = new ArrayList<>(values.size());
            for (int i = 0; i < values.size(); i++) {
                String scalar = scalarValue(location + "[" + i + "]", values.get(i), problems);
                if (scalar != null) {
                    result.add(scalar);
                }
            }
            return result;
        }
        String scalar = scalarValue(location, value, problems);
        return scalar == null ? Collections.emptyList() : Collections.singletonList(scalar);
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
