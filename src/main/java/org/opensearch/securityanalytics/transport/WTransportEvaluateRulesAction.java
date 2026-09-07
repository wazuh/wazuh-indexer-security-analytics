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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.rules.engine.LogtestQueryIndex;
import org.opensearch.securityanalytics.rules.engine.PercolateRuleEvaluator;
import org.opensearch.securityanalytics.rules.engine.PercolateRuleEvaluator.SkippedRule;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

import com.wazuh.securityanalytics.action.WEvaluateRulesAction;
import com.wazuh.securityanalytics.action.WEvaluateRulesRequest;
import com.wazuh.securityanalytics.action.WEvaluateRulesResponse;

/**
 * Transport action handler for evaluating Sigma rules against a normalized event.
 *
 * <p>Evaluation goes through the same compiler and the same percolator a deployed detector uses, so
 * a logtest result predicts the finding rather than approximating it.
 *
 * @see WEvaluateRulesAction
 * @see PercolateRuleEvaluator
 */
public class WTransportEvaluateRulesAction
        extends HandledTransportAction<WEvaluateRulesRequest, WEvaluateRulesResponse> {

    private static final Logger log = LogManager.getLogger(WTransportEvaluateRulesAction.class);

    private final ThreadPool threadPool;
    private final PercolateRuleEvaluator evaluator;

    /**
     * Constructs a new WTransportEvaluateRulesAction.
     *
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param client the OpenSearch client
     * @param clusterService the cluster service
     * @param threadPool the thread pool, used to read the caller's security context
     * @param ruleTopicIndices owner of the query index template the percolator index inherits its
     *     analysis settings from
     */
    @Inject
    public WTransportEvaluateRulesAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            ClusterService clusterService,
            ThreadPool threadPool,
            RuleTopicIndices ruleTopicIndices) {
        super(WEvaluateRulesAction.NAME, transportService, actionFilters, WEvaluateRulesRequest::new);
        this.threadPool = threadPool;
        this.evaluator =
                new PercolateRuleEvaluator(
                        client, new LogtestQueryIndex(client, clusterService, ruleTopicIndices));
    }

    @Override
    protected void doExecute(
            Task task, WEvaluateRulesRequest request, ActionListener<WEvaluateRulesResponse> listener) {
        try {
            List<SigmaRule> parsedRules = new ArrayList<>();
            List<SkippedRule> skipped = new ArrayList<>();

            List<String> ruleBodies = request.getRulesBodies();
            for (int position = 0; position < ruleBodies.size(); position++) {
                try {
                    SigmaRule parsedRule = SigmaRule.fromYaml(ruleBodies.get(position), true);
                    // fromYaml collects errors rather than throwing, so a rule can come back parsed
                    // and unusable. Rule upload refuses such a rule outright
                    // (WTransportIndexRuleAction), so a detector can never be running it; reporting
                    // it as evaluated here would be the same false confidence this endpoint exists to
                    // remove.
                    if (parsedRule.getErrors() != null && !parsedRule.getErrors().getErrors().isEmpty()) {
                        skipped.add(
                                new SkippedRule(
                                        parsedRule,
                                        PercolateRuleEvaluator.ruleId(parsedRule, position),
                                        String.format(
                                                Locale.ROOT,
                                                "the rule is not valid Sigma and would be refused on upload: %s",
                                                parsedRule.getErrors().getErrors().stream()
                                                        .map(Throwable::getMessage)
                                                        .collect(Collectors.joining("; ")))));
                        continue;
                    }
                    parsedRules.add(parsedRule);
                } catch (Exception e) {
                    log.warn("Failed to parse Sigma rule YAML: {}", e.getMessage());
                    skipped.add(
                            new SkippedRule(
                                    null,
                                    "rule_" + position,
                                    String.format(Locale.ROOT, "the rule could not be parsed: %s", e.getMessage())));
                }
            }

            // The query index and its documents belong to the plugin, not to whoever called logtest.
            this.threadPool.getThreadContext().stashContext();

            evaluator.evaluate(
                    request.getEventJson(),
                    parsedRules,
                    skipped,
                    request.getIntegrationId(),
                    request.getLogType(),
                    request.getSourceIndices(),
                    ActionListener.wrap(
                            resultJson -> listener.onResponse(new WEvaluateRulesResponse(resultJson)),
                            listener::onFailure));
        } catch (Exception e) {
            log.error("Failed to evaluate Sigma rules against event.", e);
            listener.onFailure(e);
        }
    }
}
