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
package org.opensearch.securityanalytics.transport;

import org.apache.lucene.analysis.core.WhitespaceAnalyzer;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.ContextPreservingActionListener;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchService;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.CompositeSigmaErrors;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.wazuh.securityanalytics.action.WValidateRuleAction;
import com.wazuh.securityanalytics.action.WValidateRuleRequest;
import com.wazuh.securityanalytics.action.WValidateRuleResponse;

/**
 * Transport action that validates a Sigma rule without storing it.
 *
 * <p>The rule goes through the steps storing it would: it is parsed (which checks its fields
 * against WCS) and compiled in the configuration of {@link WTransportIndexRuleAction} for a
 * Standard rule or of {@link TransportIndexRuleAction} for a custom one. Each compiled query must
 * also fit in the query index of a detector and parse, since a detector cannot run a query that
 * does not.
 *
 * @see WValidateRuleAction
 */
public class WTransportValidateRuleAction
        extends HandledTransportAction<WValidateRuleRequest, WValidateRuleResponse> {

    /**
     * Length of the id OpenSearch gives a monitor. A detector's query index stores each field of a
     * compiled query as {@code <field>_<index>_<monitor id>}.
     */
    static final int MONITOR_ID_LENGTH = 20;

    /** Events data stream assumed when no events index template is installed: the longest one. */
    static final String FALLBACK_EVENTS_INDEX = "wazuh-events-v5-access-management";

    /** Suffix of the name of the index template of each events data stream. */
    private static final String EVENTS_TEMPLATE_SUFFIX = "-template";

    /** Characters of a compiled query an error message quotes. */
    static final int QUOTED_QUERY_LENGTH = 300;

    /**
     * The OpenSearch limits a compiled query must fit in.
     *
     * @param maxLength {@code search.query.max_query_string_length}
     * @param monitorOnly {@code search.query.max_query_string_length_monitor_only}: a longer query is
     *     only logged
     * @param fieldSuffixLength characters a detector's query index adds to each field of a query
     */
    record QueryLimits(int maxLength, boolean monitorOnly, int fieldSuffixLength) {}

    private final LogTypeService logTypeService;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;

    /**
     * Constructs a new WTransportValidateRuleAction.
     *
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param logTypeService source of the field mappings a custom rule is compiled with
     * @param clusterService source of the query limits and of the events data streams
     * @param threadPool the thread pool, used to read the field mappings as the plugin
     */
    @Inject
    public WTransportValidateRuleAction(
            TransportService transportService,
            ActionFilters actionFilters,
            LogTypeService logTypeService,
            ClusterService clusterService,
            ThreadPool threadPool) {
        super(WValidateRuleAction.NAME, transportService, actionFilters, WValidateRuleRequest::new);
        this.logTypeService = logTypeService;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(
            Task task, WValidateRuleRequest request, ActionListener<WValidateRuleResponse> listener) {
        QueryLimits limits = this.queryLimits();
        if (!request.isCustom()) {
            this.respond(request.getRule(), Collections.emptyMap(), false, limits, listener);
            return;
        }
        // The log type configuration belongs to the plugin, not to whoever asked for the validation.
        // The caller's context is restored for the answer.
        ThreadContext threadContext = this.threadPool.getThreadContext();
        ActionListener<WValidateRuleResponse> restoring =
                ContextPreservingActionListener.wrapPreservingContext(listener, threadContext);
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            this.logTypeService.getRuleFieldMappings(
                    request.getLogType(),
                    ActionListener.wrap(
                            fieldMappings ->
                                    this.respond(request.getRule(), fieldMappings, true, limits, restoring),
                            restoring::onFailure));
        }
    }

    /** Reads the query limits from the cluster settings, and the longest events data stream name. */
    private QueryLimits queryLimits() {
        ClusterSettings settings = this.clusterService.getClusterSettings();
        int longestIndex =
                this.clusterService.state().metadata().templatesV2().keySet().stream()
                        .filter(name -> name.startsWith(IndexUtils.WCS_EVENTS_INDEX_PREFIX + "-"))
                        .filter(name -> name.endsWith(EVENTS_TEMPLATE_SUFFIX))
                        .mapToInt(name -> name.length() - EVENTS_TEMPLATE_SUFFIX.length())
                        .max()
                        .orElse(FALLBACK_EVENTS_INDEX.length());
        return new QueryLimits(
                settings.get(SearchService.SEARCH_MAX_QUERY_STRING_LENGTH),
                settings.get(SearchService.SEARCH_MAX_QUERY_STRING_LENGTH_MONITOR_ONLY),
                1 + longestIndex + 1 + MONITOR_ID_LENGTH);
    }

    private void respond(
            String rule,
            Map<String, String> fieldMappings,
            boolean custom,
            QueryLimits limits,
            ActionListener<WValidateRuleResponse> listener) {
        try {
            listener.onResponse(new WValidateRuleResponse(validate(rule, fieldMappings, custom, limits)));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    /**
     * Parses and compiles a rule, and checks that every compiled query fits in a detector's query
     * index and parses.
     *
     * @param rule the rule body, YAML or JSON
     * @param fieldMappings the field mappings of a custom rule, empty for a Standard rule
     * @param custom whether the rule is compiled as a custom rule
     * @param limits the limits a compiled query must fit in
     * @return the compiled queries
     * @throws SecurityAnalyticsException with status 400, naming the reason, if the rule is invalid
     */
    static List<String> validate(
            String rule, Map<String, String> fieldMappings, boolean custom, QueryLimits limits) {
        List<Object> queries;
        Set<String> fields;
        try {
            SigmaRule parsedRule = SigmaRule.fromYaml(rule, true);
            if (parsedRule.getErrors() != null && !parsedRule.getErrors().getErrors().isEmpty()) {
                throw SecurityAnalyticsException.wrap(parsedRule.getErrors());
            }
            QueryBackend backend = new OSQueryBackend(fieldMappings, custom);
            queries = backend.convertRule(parsedRule);
            fields = backend.getQueryFields().keySet();
        } catch (SecurityAnalyticsException e) {
            throw e;
        } catch (CompositeSigmaErrors e) {
            throw (SecurityAnalyticsException) SecurityAnalyticsException.wrap(e);
        } catch (Exception e) {
            throw new SecurityAnalyticsException(
                    String.format(Locale.ROOT, "The rule does not compile: %s", e.getMessage()),
                    RestStatus.BAD_REQUEST,
                    e);
        }
        List<String> compiled = new ArrayList<>(queries.size());
        for (Object query : queries) {
            String text = query.toString();
            requireFits(text, fields, limits);
            requireParses(text);
            compiled.add(text);
        }
        return compiled;
    }

    /**
     * Checks that a compiled query is not longer than {@code search.query.max_query_string_length}
     * once a detector's query index has renamed its fields. A longer query is never stored, so the
     * rule would never match. When the limit only logs ({@code
     * search.query.max_query_string_length_monitor_only}), any length is accepted.
     *
     * @param query the compiled query
     * @param fields the fields the query uses
     * @param limits the limits a compiled query must fit in
     * @throws SecurityAnalyticsException with status 400 if the query is too long
     */
    static void requireFits(String query, Set<String> fields, QueryLimits limits) {
        if (limits.monitorOnly()) {
            return;
        }
        long length = storedLength(query, fields, limits.fieldSuffixLength());
        if (length > limits.maxLength()) {
            throw new SecurityAnalyticsException(
                    String.format(
                            Locale.ROOT,
                            "The rule compiles to a query of about %d characters once a detector stores it,"
                                    + " more than the %d of search.query.max_query_string_length, so it would never"
                                    + " match. Query: %s",
                            length,
                            limits.maxLength(),
                            quote(query)),
                    RestStatus.BAD_REQUEST,
                    null);
        }
    }

    /**
     * Length of a compiled query as a detector's query index stores it: Alerting appends the index
     * and the monitor id to each field the query names, after {@code <field>:} or {@code _exists_:}.
     *
     * @param query the compiled query
     * @param fields the fields the query uses
     * @param fieldSuffixLength characters added to each field
     * @return the stored length
     */
    static long storedLength(String query, Set<String> fields, int fieldSuffixLength) {
        long references = 0;
        for (String field : fields) {
            references += occurrences(query, field + ":");
            references += occurrences(query, "_exists_: " + field);
        }
        return query.length() + references * fieldSuffixLength;
    }

    private static int occurrences(String text, String part) {
        int count = 0;
        for (int i = text.indexOf(part); i >= 0; i = text.indexOf(part, i + part.length())) {
            count++;
        }
        return count;
    }

    /**
     * Checks that a compiled query parses as the query string a detector runs.
     *
     * @param query the compiled query
     * @throws SecurityAnalyticsException with status 400 if the query does not parse
     */
    static void requireParses(String query) {
        try {
            QueryParser parser = new QueryParser("_default", new WhitespaceAnalyzer());
            parser.setAllowLeadingWildcard(true);
            parser.parse(query);
        } catch (ParseException | RuntimeException e) {
            String message =
                    e.getCause() instanceof IndexSearcher.TooManyClauses
                                    || e instanceof IndexSearcher.TooManyClauses
                            ? String.format(
                                    Locale.ROOT,
                                    "The rule compiles to a query of more than %d clauses, the limit of"
                                            + " indices.query.bool.max_clause_count. Query: %s",
                                    IndexSearcher.getMaxClauseCount(),
                                    quote(query))
                            : String.format(
                                    Locale.ROOT,
                                    "The rule compiles to a query that does not parse: %s",
                                    quote(query));
            throw new SecurityAnalyticsException(message, RestStatus.BAD_REQUEST, e);
        }
    }

    /** The start of a query, for an error message: a query can be tens of thousands of characters. */
    static String quote(String query) {
        if (query.length() <= QUOTED_QUERY_LENGTH) {
            return query;
        }
        return String.format(
                Locale.ROOT,
                "%s... (%d characters)",
                query.substring(0, QUOTED_QUERY_LENGTH),
                query.length());
    }
}
