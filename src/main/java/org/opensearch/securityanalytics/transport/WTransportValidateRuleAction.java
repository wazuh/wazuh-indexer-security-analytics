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
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.CompositeSigmaErrors;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.wazuh.securityanalytics.action.WValidateRuleAction;
import com.wazuh.securityanalytics.action.WValidateRuleRequest;
import com.wazuh.securityanalytics.action.WValidateRuleResponse;

/**
 * Transport action that validates a Sigma rule without storing it.
 *
 * <p>The rule goes through the steps storing it would: it is parsed (which checks its fields
 * against WCS) and compiled in the configuration of {@link WTransportIndexRuleAction} for a
 * Standard rule or of {@link TransportIndexRuleAction} for a custom one. Each compiled query must
 * also parse, since a detector cannot run a query that does not.
 *
 * @see WValidateRuleAction
 */
public class WTransportValidateRuleAction
        extends HandledTransportAction<WValidateRuleRequest, WValidateRuleResponse> {

    private final LogTypeService logTypeService;
    private final ThreadPool threadPool;

    /**
     * Constructs a new WTransportValidateRuleAction.
     *
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param logTypeService source of the field mappings a custom rule is compiled with
     * @param threadPool the thread pool, used to read the field mappings as the plugin
     */
    @Inject
    public WTransportValidateRuleAction(
            TransportService transportService,
            ActionFilters actionFilters,
            LogTypeService logTypeService,
            ThreadPool threadPool) {
        super(WValidateRuleAction.NAME, transportService, actionFilters, WValidateRuleRequest::new);
        this.logTypeService = logTypeService;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(
            Task task, WValidateRuleRequest request, ActionListener<WValidateRuleResponse> listener) {
        if (!request.isCustom()) {
            this.respond(request.getRule(), Collections.emptyMap(), false, listener);
            return;
        }
        // The log type configuration belongs to the plugin, not to whoever asked for the validation.
        this.threadPool.getThreadContext().stashContext();
        this.logTypeService.getRuleFieldMappings(
                request.getLogType(),
                ActionListener.wrap(
                        fieldMappings -> this.respond(request.getRule(), fieldMappings, true, listener),
                        listener::onFailure));
    }

    private void respond(
            String rule,
            Map<String, String> fieldMappings,
            boolean custom,
            ActionListener<WValidateRuleResponse> listener) {
        try {
            listener.onResponse(new WValidateRuleResponse(validate(rule, fieldMappings, custom)));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    /**
     * Parses and compiles a rule, and checks that every compiled query parses.
     *
     * @param rule the rule body, YAML or JSON
     * @param fieldMappings the field mappings of a custom rule, empty for a Standard rule
     * @param custom whether the rule is compiled as a custom rule
     * @return the compiled queries
     * @throws SecurityAnalyticsException with status 400, naming the reason, if the rule is invalid
     */
    static List<String> validate(String rule, Map<String, String> fieldMappings, boolean custom) {
        List<Object> queries;
        try {
            SigmaRule parsedRule = SigmaRule.fromYaml(rule, true);
            if (parsedRule.getErrors() != null && !parsedRule.getErrors().getErrors().isEmpty()) {
                throw SecurityAnalyticsException.wrap(parsedRule.getErrors());
            }
            QueryBackend backend = new OSQueryBackend(fieldMappings, custom);
            queries = backend.convertRule(parsedRule);
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
            requireParses(text);
            compiled.add(text);
        }
        return compiled;
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
            throw new SecurityAnalyticsException(
                    String.format(Locale.ROOT, "The rule compiles to a query that does not parse: %s", query),
                    RestStatus.BAD_REQUEST,
                    e);
        }
    }
}
