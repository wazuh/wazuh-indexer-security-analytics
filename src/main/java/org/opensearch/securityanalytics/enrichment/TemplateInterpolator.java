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
package org.opensearch.securityanalytics.enrichment;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves {@code {{ field.path }}} placeholders in rule metadata fields against the triggering
 * event's {@code _source} map.
 *
 * <p>Supported field types:
 *
 * <ul>
 *   <li><b>String</b> ({@link #interpolate}): each placeholder is replaced with the scalar string
 *       representation of the resolved value, or an empty string on miss.
 *   <li><b>List&lt;String&gt;</b> ({@link #interpolateList}): pure-placeholder elements may expand
 *       into multiple values when the resolved field is a list; duplicates are removed.
 *   <li><b>Map&lt;String, List&lt;String&gt;&gt;</b> ({@link #interpolateMapOfLists}): applies list
 *       interpolation to each value; keys whose list becomes empty are dropped.
 * </ul>
 */
public final class TemplateInterpolator {

    /** Matches {@code {{ path }}} with optional inner whitespace. */
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{\\s*(.+?)\\s*}}");

    /**
     * Pattern that matches a string consisting of exactly one placeholder and nothing else. Used to
     * detect pure-placeholder list elements eligible for array expansion.
     */
    private static final Pattern PURE_PLACEHOLDER = Pattern.compile("^\\{\\{\\s*(.+?)\\s*}}$");

    private TemplateInterpolator() {}

    // String interpolation

    /**
     * Resolves all {@code {{ field.path }}} placeholders in {@code template} against {@code source}.
     *
     * <ul>
     *   <li>Scalar resolved value (String, Number, Boolean) -> {@code toString()} substitution.
     *   <li>Missing, {@code null}, or non-scalar (Map, List) -> empty string.
     * </ul>
     *
     * @param template the template string, may be {@code null}
     * @param source the event {@code _source} map
     * @return the interpolated string, or {@code null} if {@code template} is {@code null}
     */
    public static String interpolate(String template, Map<String, Object> source) {
        if (template == null || source == null) {
            return template;
        }
        Matcher matcher = PLACEHOLDER.matcher(template);
        if (!matcher.find()) {
            return template;
        }
        StringBuilder sb = new StringBuilder();
        do {
            String path = matcher.group(1);
            Object value = resolvePath(path, source);
            String replacement = scalarToString(value);
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        } while (matcher.find());
        matcher.appendTail(sb);
        return sb.toString();
    }

    // List interpolation

    /**
     * Interpolates a list of strings, supporting array expansion for pure-placeholder elements.
     *
     * <p>For each element:
     *
     * <ul>
     *   <li><b>Pure placeholder</b> (entire string is {@code {{ path }}}):
     *       <ul>
     *         <li>Resolved to scalar -> single string element.
     *         <li>Resolved to {@code List} -> each scalar element is flattened into the result.
     *         <li>Resolved to {@code null}/missing/{@code Map} -> element is dropped.
     *       </ul>
     *   <li><b>Mixed text + placeholders</b> -> normal string interpolation via {@link #interpolate};
     *       if the result is blank, the element is dropped.
     *   <li><b>Plain string</b> (no placeholders) -> passed through unchanged.
     * </ul>
     *
     * <p>Duplicates are removed while preserving insertion order.
     *
     * @param items the list of strings to interpolate, may be {@code null}
     * @param source the event {@code _source} map
     * @return a new list with interpolated, deduplicated values
     */
    public static List<String> interpolateList(List<String> items, Map<String, Object> source) {
        if (items == null || items.isEmpty()) {
            return items == null ? null : List.of();
        }
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String item : items) {
            if (item == null) {
                continue;
            }
            Matcher pureMatcher = PURE_PLACEHOLDER.matcher(item);
            if (pureMatcher.matches()) {
                // Pure placeholder - eligible for array expansion
                String path = pureMatcher.group(1);
                Object value = resolvePath(path, source);
                expandValue(value, result);
            } else if (PLACEHOLDER.matcher(item).find()) {
                // Mixed text + placeholders - normal string interpolation
                String interpolated = interpolate(item, source);
                if (interpolated != null && !interpolated.isEmpty()) {
                    result.add(interpolated);
                }
            } else {
                // Plain string
                result.add(item);
            }
        }
        return new ArrayList<>(result);
    }

    // Map<String, List<String>> interpolation

    /**
     * Interpolates each value list in a {@code Map<String, List<String>>} (e.g., compliance or
     * mitre). Keys whose value list becomes empty after interpolation are removed.
     *
     * @param map the map to interpolate, may be {@code null}
     * @param source the event {@code _source} map
     * @return a new map with interpolated values
     */
    public static Map<String, List<String>> interpolateMapOfLists(
            Map<String, ?> map, Map<String, Object> source) {
        if (map == null || map.isEmpty()) {
            return map == null ? null : Map.of();
        }
        LinkedHashMap<String, List<String>> result = new LinkedHashMap<>();
        for (Map.Entry<String, ?> entry : map.entrySet()) {
            Object rawValue = entry.getValue();
            List<String> valueList;
            if (rawValue instanceof List) {
                // Coerce each element to String for safety (values may be stored as mixed types)
                List<String> stringList = new ArrayList<>();
                for (Object elem : (List<?>) rawValue) {
                    stringList.add(elem == null ? null : elem.toString());
                }
                valueList = stringList;
            } else {
                continue;
            }
            List<String> interpolated = interpolateList(valueList, source);
            if (interpolated != null && !interpolated.isEmpty()) {
                result.put(entry.getKey(), interpolated);
            }
        }
        return result;
    }

    // Path resolution

    /**
     * Walks a dot-separated path in a nested map. Returns the leaf value, or {@code null} if any
     * segment is missing, {@code null}, or not a {@code Map}.
     *
     * @param dotPath the dot-separated field path (e.g., {@code "wazuh.agent.id"})
     * @param source the root map
     * @return the resolved value, or {@code null}
     */
    @SuppressWarnings("unchecked")
    static Object resolvePath(String dotPath, Map<String, Object> source) {
        if (dotPath == null || dotPath.isEmpty() || source == null) {
            return null;
        }
        String[] segments = dotPath.split("\\.");
        Object current = source;
        for (String segment : segments) {
            if (!(current instanceof Map)) {
                return null;
            }
            current = ((Map<String, Object>) current).get(segment);
            if (current == null) {
                return null;
            }
        }
        return current;
    }

    // Helpers

    /**
     * Returns the string representation of a scalar value, or an empty string for {@code null},
     * {@code Map}, or {@code List} values.
     */
    private static String scalarToString(Object value) {
        if (value == null || value instanceof Map || value instanceof List) {
            return "";
        }
        return value.toString();
    }

    /**
     * Expands a resolved value into the result set. Scalars are added as single elements; lists have
     * each scalar element added individually; nulls, Maps, and empty results are skipped.
     */
    private static void expandValue(Object value, LinkedHashSet<String> result) {
        if (value == null || value instanceof Map) {
            return;
        }
        if (value instanceof List) {
            for (Object elem : (List<?>) value) {
                if (elem != null && !(elem instanceof Map) && !(elem instanceof List)) {
                    String str = elem.toString();
                    if (!str.isEmpty()) {
                        result.add(str);
                    }
                }
            }
        } else {
            String str = value.toString();
            if (!str.isEmpty()) {
                result.add(str);
            }
        }
    }
}
