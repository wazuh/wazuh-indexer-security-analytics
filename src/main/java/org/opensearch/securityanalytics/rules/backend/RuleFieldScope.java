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
package org.opensearch.securityanalytics.rules.backend;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

/**
 * Tells which fields of an event a rule can match.
 *
 * <p>A rule's {@code query_field_names} lists the fields its conditions name. A Sigma {@code
 * keywords} list names none: it compiles to a query term with no field qualifier, which the
 * percolator evaluates against every field of the event. A rule holding such a condition cannot be
 * scoped to its field names.
 */
public final class RuleFieldScope {

    private static final Logger log = LogManager.getLogger(RuleFieldScope.class);

    private RuleFieldScope() {}

    /**
     * Tells whether a stored rule holds a condition that names no field, and so can match a value in
     * any field of the event.
     *
     * <p>A rule naming no field at all is made only of such conditions. A rule naming some fields may
     * still combine them with a keyword ({@code keywords and selection}), which only its compiled
     * conditions reveal, so it is compiled again. That happens when a detector is created or updated,
     * never per event.
     *
     * @param rule the stored rule.
     * @return {@code true} when the rule can match a value in any field; {@code false} when it only
     *     matches the fields it names, or when its body cannot be compiled to tell.
     */
    public static boolean matchesAnyField(Rule rule) {
        if (rule.getQueryFieldNames() == null || rule.getQueryFieldNames().isEmpty()) {
            return true;
        }
        String body = rule.getRule();
        if (body == null || body.isBlank()) {
            return false;
        }
        try {
            SigmaRule parsed = SigmaRule.fromYaml(body, true);
            if (parsed.getErrors() != null && !parsed.getErrors().getErrors().isEmpty()) {
                return false;
            }
            Backend backend = new Backend();
            backend.convertRule(parsed);
            return backend.matchesAnyField();
        } catch (Exception e) {
            // The rule was compiled when it was stored, so this is not expected. Keeping its field names
            // is what the detector did before this check existed.
            log.debug(
                    "Could not tell whether rule [{}] names every field it matches: {}",
                    rule.getId(),
                    e.getMessage());
            return false;
        }
    }

    /**
     * The rule compiler, recording whether the last rule it converted holds a condition that names no
     * field.
     *
     * <p>It compiles exactly as {@link OSQueryBackend} does and only observes. Kept in a subclass so
     * that {@link QueryBackend} and {@link OSQueryBackend}, which are upstream code, stay untouched.
     */
    public static class Backend extends OSQueryBackend {

        private boolean unbound;

        /**
         * Builds the compiler with the arguments rule upload uses.
         *
         * @throws IOException if the backend cannot load its configuration.
         */
        public Backend() throws IOException {
            super(Collections.emptyMap(), false);
        }

        @Override
        public List<Object> convertRule(SigmaRule rule) throws SigmaValueError, SigmaConditionError {
            unbound = false;
            return super.convertRule(rule);
        }

        @Override
        public Object convertConditionValStr(ConditionValueExpression condition, boolean applyDeMorgans)
                throws SigmaValueError {
            unbound = true;
            return super.convertConditionValStr(condition, applyDeMorgans);
        }

        @Override
        public Object convertConditionValNum(
                ConditionValueExpression condition, boolean applyDeMorgans) {
            unbound = true;
            return super.convertConditionValNum(condition, applyDeMorgans);
        }

        @Override
        public Object convertConditionValRe(
                ConditionValueExpression condition, boolean applyDeMorgans) {
            unbound = true;
            return super.convertConditionValRe(condition, applyDeMorgans);
        }

        /**
         * Tells whether the last rule passed to {@link #convertRule} holds a condition that names no
         * field.
         *
         * @return {@code true} when that rule can match a value in any field of the event.
         */
        public boolean matchesAnyField() {
            return unbound;
        }
    }
}
