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
 * percolator evaluates against every field of the event. A rule that also names fields ({@code
 * keywords and selection}) has non-empty field names, so only its compiled conditions reveal the
 * keyword: {@link Backend} records it while compiling.
 */
public final class RuleFieldScope {

    private RuleFieldScope() {}

    /**
     * Gives the field names a detector's doc-level query carries for a rule.
     *
     * <p>Alerting reads only the fields the queries of a monitor name, unless one of them names none,
     * and then it reads the whole event. A rule that names no field (a Sigma {@code keywords} list)
     * gets no field names, so that its keywords are matched against every field of the event and not
     * only the fields the other rules happen to name.
     *
     * <p>A rule that names some field keeps the detector's list, also when it holds a keyword too.
     * Alerting uses the list to rewrite the clauses on fields the events index does not map yet
     * (wazuh/wazuh-indexer-plugins#1518); without it the percolator rejects the query and the rule is
     * never evaluated. Its keywords then reach the whole event only when the detector also holds a
     * rule that names no field.
     *
     * @param rule the rule the query is built from.
     * @param detectorFieldNames the fields named by all the rules of the detector.
     * @return an empty list for a rule that names no field, {@code detectorFieldNames} otherwise.
     */
    public static List<String> monitorQueryFieldNames(Rule rule, List<String> detectorFieldNames) {
        if (rule.getQueryFieldNames() == null || rule.getQueryFieldNames().isEmpty()) {
            return Collections.emptyList();
        }
        return detectorFieldNames;
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
