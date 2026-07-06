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
package org.opensearch.securityanalytics.resthandler;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Validates and normalizes the {@code wazuh.case} object accepted by {@link
 * RestUpdateFindingsAction} so that it conforms to the Wazuh Common Schema (WCS).
 *
 * <p>Unknown fields, invalid enum values and malformed comment entries are rejected. Enum values
 * are normalized to lowercase, except {@code tlp}, which is uppercased and must keep its {@code
 * TLP:} prefix (e.g. {@code TLP:CLEAR}).
 */
final class CaseValidator {

    private CaseValidator() {}

    /** Allowed top-level keys under {@code wazuh.case}. */
    private static final Set<String> CASE_FIELDS =
            Set.of(
                    "title",
                    "description",
                    "status",
                    "severity",
                    "priority",
                    "tlp",
                    "tags",
                    "created_at",
                    "updated_at",
                    "user",
                    "comments");

    private static final Set<String> USER_FIELDS = Set.of("name");
    private static final Set<String> COMMENT_FIELDS =
            Set.of("author", "comment", "created_at", "updated_at");

    private static final Set<String> STATUS_VALUES =
            Set.of("active", "acknowledged", "completed", "error", "deleted", "audit");
    private static final Set<String> SEVERITY_VALUES =
            Set.of("informational", "low", "medium", "high", "critical");
    private static final Set<String> PRIORITY_VALUES = Set.of("low", "medium", "high", "urgent");
    private static final Set<String> TLP_VALUES =
            Set.of("TLP:RED", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR");

    /**
     * Validates the given case object against the WCS and normalizes its enum values in place.
     *
     * @param caseObj the mutable {@code case} map from the request
     * @return {@code null} if the object is valid, or a human-readable message describing the first
     *     problem found
     */
    static String validateAndNormalize(Map<String, Object> caseObj) {
        for (String key : caseObj.keySet()) {
            if (!CASE_FIELDS.contains(key)) {
                return "unknown case field \"" + key + "\"";
            }
        }

        String error;
        if ((error = normalizeEnum(caseObj, "status", STATUS_VALUES, false)) != null) return error;
        if ((error = normalizeEnum(caseObj, "severity", SEVERITY_VALUES, false)) != null) return error;
        if ((error = normalizeEnum(caseObj, "priority", PRIORITY_VALUES, false)) != null) return error;
        if ((error = normalizeEnum(caseObj, "tlp", TLP_VALUES, true)) != null) return error;

        if ((error = validateString(caseObj.get("title"), "title")) != null) return error;
        if ((error = validateString(caseObj.get("description"), "description")) != null) return error;
        if ((error = validateTimestamp(caseObj.get("created_at"), "created_at")) != null) return error;
        if ((error = validateTimestamp(caseObj.get("updated_at"), "updated_at")) != null) return error;

        if ((error = validateTags(caseObj)) != null) return error;
        if ((error = validateUser(caseObj)) != null) return error;
        return validateComments(caseObj);
    }

    /**
     * Lowercases (or uppercases, for {@code tlp}) an enum value and checks it against the WCS set.
     */
    private static String normalizeEnum(
            Map<String, Object> caseObj, String field, Set<String> allowed, boolean upper) {
        Object value = caseObj.get(field);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String)) {
            return field + " must be a string";
        }
        String normalized =
                upper
                        ? ((String) value).toUpperCase(Locale.ROOT)
                        : ((String) value).toLowerCase(Locale.ROOT);
        if (!allowed.contains(normalized)) {
            return "invalid " + field + " value \"" + value + "\"; allowed values: " + allowed;
        }
        caseObj.put(field, normalized);
        return null;
    }

    private static String validateString(Object value, String label) {
        if (value != null && !(value instanceof String)) {
            return label + " must be a string";
        }
        return null;
    }

    /** A timestamp may be an ISO-8601 string or an epoch-millis number. */
    private static String validateTimestamp(Object value, String label) {
        if (value == null || value instanceof String || value instanceof Number) {
            return null;
        }
        return label + " must be a string or number";
    }

    private static String validateTags(Map<String, Object> caseObj) {
        Object value = caseObj.get("tags");
        if (value == null) {
            return null;
        }
        if (!(value instanceof List)) {
            return "tags must be an array of strings";
        }
        for (Object tag : (List<?>) value) {
            if (!(tag instanceof String)) {
                return "tags must be an array of strings";
            }
        }
        return null;
    }

    private static String validateUser(Map<String, Object> caseObj) {
        Object value = caseObj.get("user");
        if (value == null) {
            return null;
        }
        if (!(value instanceof Map)) {
            return "user must be an object";
        }
        Map<?, ?> user = (Map<?, ?>) value;
        for (Object key : user.keySet()) {
            if (!USER_FIELDS.contains(key)) {
                return "unknown user field \"" + key + "\"";
            }
        }
        return validateString(user.get("name"), "user.name");
    }

    private static String validateComments(Map<String, Object> caseObj) {
        Object value = caseObj.get("comments");
        if (value == null) {
            return null;
        }
        if (!(value instanceof List)) {
            return "comments must be an array";
        }
        List<?> comments = (List<?>) value;
        for (int i = 0; i < comments.size(); i++) {
            Object element = comments.get(i);
            if (!(element instanceof Map)) {
                return "comment at index " + i + " must be an object";
            }
            Map<?, ?> comment = (Map<?, ?>) element;
            for (Object key : comment.keySet()) {
                if (!COMMENT_FIELDS.contains(key)) {
                    return "unknown comment field \"" + key + "\" at index " + i;
                }
            }
            String error;
            if ((error = validateString(comment.get("comment"), "comment.comment at index " + i)) != null)
                return error;
            if ((error = validateString(comment.get("author"), "comment.author at index " + i)) != null)
                return error;
            if ((error = validateTimestamp(comment.get("created_at"), "comment.created_at at index " + i))
                    != null) return error;
            if ((error = validateTimestamp(comment.get("updated_at"), "comment.updated_at at index " + i))
                    != null) return error;
        }
        return null;
    }
}
