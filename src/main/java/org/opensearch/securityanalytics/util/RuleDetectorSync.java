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
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/**
 * Keeps detectors in sync with the rules they reference.
 *
 * <p>A detector compiles its rules into an alerting monitor when it is created or updated; the
 * monitor is not re-evaluated afterwards. So when a rule changes in a way that affects compilation
 * (for example, when it is disabled), every detector that references it must be rebuilt for the
 * change to take effect. Used by both the custom and pre-packaged rules paths.
 */
public final class RuleDetectorSync {

    private static final Logger log = LogManager.getLogger(RuleDetectorSync.class);

    private static final String INPUT_BASE = "detector.inputs.detector_input.";

    private RuleDetectorSync() {}

    /**
     * Builds a query matching detectors that reference the given rule id through the given nested
     * rules field ({@code custom_rules} or {@code pre_packaged_rules}).
     *
     * @param nestedRulesField the detector input rules field name
     * @param ruleId the rule id referenced by the detector
     * @return a nested query over the detectors index
     */
    public static QueryBuilder detectorsReferencingRuleQuery(String nestedRulesField, String ruleId) {
        String path = INPUT_BASE + nestedRulesField;
        return QueryBuilders.nestedQuery(
                path,
                QueryBuilders.boolQuery().must(QueryBuilders.matchQuery(path + ".id", ruleId)),
                ScoreMode.Avg);
    }

    /**
     * Whether a detector references any of the given rule ids, as a custom or as a pre-packaged rule.
     * The ids are compared exactly: the detectors index maps them as analyzed text, so a query on
     * them would also match detectors that share only part of an id.
     *
     * @param detector the detector
     * @param ruleIds the rule ids
     * @return true if the detector references one of the rules
     */
    public static boolean referencesAnyRule(Detector detector, Set<String> ruleIds) {
        for (DetectorInput input : detector.getInputs()) {
            for (List<DetectorRule> rules :
                    List.of(input.getCustomRules(), input.getPrePackagedRules())) {
                for (DetectorRule rule : rules) {
                    if (ruleIds.contains(rule.getId())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Rebuilds every detector that references the given rule so its Monitor is recompiled from the
     * current rule content. Best-effort: individual detector failures are logged but do not fail the
     * overall operation, so a rule write is never blocked by a detector rebuild problem.
     *
     * @param client the OpenSearch client
     * @param xContentRegistry registry used to parse detector documents
     * @param nestedRulesField {@code custom_rules} or {@code pre_packaged_rules}
     * @param ruleId the id of the rule that changed
     * @param refreshPolicy refresh policy for the detector re-index
     * @param listener notified once all referencing detectors have been rebuilt (or none were found)
     */
    public static void rebuildDetectorsForRule(
            Client client,
            NamedXContentRegistry xContentRegistry,
            String nestedRulesField,
            String ruleId,
            WriteRequest.RefreshPolicy refreshPolicy,
            ActionListener<Void> listener) {
        rebuildDetectors(
                client,
                xContentRegistry,
                detectorsReferencingRuleQuery(nestedRulesField, ruleId),
                detector -> true,
                "rule [" + ruleId + "]",
                refreshPolicy,
                ActionListener.wrap(rebuilt -> listener.onResponse(null), listener::onFailure));
    }

    /**
     * Rebuilds once every detector that references any of the given rules, as a custom or as a
     * pre-packaged rule, so their Monitors are recompiled from the current rule content. A detector
     * that references several of the rules is rebuilt once. Best-effort, like {@link
     * #rebuildDetectorsForRule}.
     *
     * @param client the OpenSearch client
     * @param xContentRegistry registry used to parse detector documents
     * @param ruleIds the ids of the rules that changed
     * @param refreshPolicy refresh policy for the detector re-index
     * @param listener notified with the number of detectors rebuilt
     */
    public static void rebuildDetectorsForRules(
            Client client,
            NamedXContentRegistry xContentRegistry,
            Collection<String> ruleIds,
            WriteRequest.RefreshPolicy refreshPolicy,
            ActionListener<Integer> listener) {
        // Read every detector and pick the referencing ones here: a query with one clause per rule
        // id would exceed the maximum clause count for the rule sets of a CTI sync, and there are
        // few detectors.
        Set<String> ids = new HashSet<>(ruleIds);
        rebuildDetectors(
                client,
                xContentRegistry,
                QueryBuilders.matchAllQuery(),
                detector -> referencesAnyRule(detector, ids),
                ids.size() + " rules",
                refreshPolicy,
                listener);
    }

    /**
     * Rebuilds every detector that matches the query and the predicate.
     *
     * @param listener notified with the number of detectors rebuilt
     */
    private static void rebuildDetectors(
            Client client,
            NamedXContentRegistry xContentRegistry,
            QueryBuilder query,
            Predicate<Detector> keep,
            String change,
            WriteRequest.RefreshPolicy refreshPolicy,
            ActionListener<Integer> listener) {
        SearchRequest searchRequest =
                new SearchRequest(Detector.DETECTORS_INDEX)
                        .source(
                                new SearchSourceBuilder()
                                        .seqNoAndPrimaryTerm(true)
                                        .version(true)
                                        .query(query)
                                        .size(10000))
                        // Tolerate a missing detectors index (no detectors created yet): treat it as
                        // an empty result instead of failing, keeping this best-effort.
                        .indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN)
                        .preference(Preference.PRIMARY_FIRST.type());

        client.search(
                searchRequest,
                ActionListener.wrap(
                        response -> {
                            SearchHits hits = response.getHits();
                            if (hits.getHits().length == 0) {
                                listener.onResponse(0);
                                return;
                            }

                            List<Detector> detectors = new ArrayList<>();
                            for (SearchHit hit : hits) {
                                try (XContentParser xcp =
                                        XContentType.JSON
                                                .xContent()
                                                .createParser(
                                                        xContentRegistry,
                                                        LoggingDeprecationHandler.INSTANCE,
                                                        hit.getSourceAsString())) {
                                    Detector detector = Detector.docParse(xcp, hit.getId(), hit.getVersion());
                                    if (keep.test(detector)) {
                                        detectors.add(detector);
                                    }
                                } catch (Exception e) {
                                    log.error(
                                            "Failed to parse detector [{}] while syncing {}", hit.getId(), change, e);
                                }
                            }

                            if (detectors.isEmpty()) {
                                listener.onResponse(0);
                                return;
                            }

                            AtomicInteger remaining = new AtomicInteger(detectors.size());
                            AtomicInteger rebuilt = new AtomicInteger();
                            for (Detector detector : detectors) {
                                IndexDetectorRequest indexRequest =
                                        new IndexDetectorRequest(
                                                detector.getId(), refreshPolicy, RestRequest.Method.PUT, detector);
                                client.execute(
                                        IndexDetectorAction.INSTANCE,
                                        indexRequest,
                                        ActionListener.wrap(
                                                r -> {
                                                    log.debug(
                                                            "Rebuilt detector [{}] after change to {}", detector.getId(), change);
                                                    rebuilt.incrementAndGet();
                                                    if (remaining.decrementAndGet() == 0) {
                                                        listener.onResponse(rebuilt.get());
                                                    }
                                                },
                                                e -> {
                                                    log.error(
                                                            "Failed to rebuild detector [{}] after change to {}",
                                                            detector.getId(),
                                                            change,
                                                            e);
                                                    if (remaining.decrementAndGet() == 0) {
                                                        listener.onResponse(rebuilt.get());
                                                    }
                                                }));
                            }
                        },
                        e -> {
                            // Best-effort: a failed detector lookup must not break the rule write.
                            log.error("Failed to search detectors referencing {}", change, e);
                            listener.onResponse(0);
                        }));
    }
}
