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
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Keeps detectors in sync with the rules they reference.
 *
 * <p>A detector compiles its rules into an alerting monitor when it is created or updated; the
 * monitor is not re-evaluated afterwards. So when a rule changes in a way that affects compilation
 * (for example, when it is disabled), every detector that references it must be rebuilt for the
 * change to take effect. Used by both the custom and pre-packaged rules paths.
 *
 * <p>Rebuilds of the same detector are coalesced. A ruleset update changes many rules at once and
 * the caller issues them in parallel, so one detector can be asked to rebuild dozens of times over
 * a few seconds. Each rebuild reads the detector, and an update that leaves it with no monitors
 * deletes its workflow, so overlapping rebuilds delete what the others still expect to find and the
 * detector is left unable to rebuild until some later pass fixes it. Running one rebuild at a time
 * per detector, with a single trailing pass for whatever changed meanwhile, produces the same end
 * state: the rebuild recompiles the monitor from the rules as they are at that moment, not from the
 * rule that triggered it.
 *
 * <p>Every referencing detector is rebuilt, including the ones the Content Manager owns. Its
 * detector phase rebuilds those from their integration document, but it only sends the integrations
 * that still have an enabled rule: an integration whose rules are all disabled builds no request,
 * so nothing there stops the detector it already created. What stops it is this rebuild, which
 * leaves it with no monitors.
 *
 * <p>See wazuh/wazuh-indexer-plugins#1837.
 */
public final class RuleDetectorSync {

    private static final Logger log = LogManager.getLogger(RuleDetectorSync.class);

    private static final String INPUT_BASE = "detector.inputs.detector_input.";

    /**
     * Detector ids with a rebuild in flight on this node, mapped to whether another one is owed once
     * it finishes. A detector is in the map only while it is being rebuilt, so the map is empty
     * whenever nothing is in flight.
     */
    private static final Map<String, Boolean> REBUILDS_IN_FLIGHT = new ConcurrentHashMap<>();

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
        SearchRequest searchRequest =
                new SearchRequest(Detector.DETECTORS_INDEX)
                        .source(
                                new SearchSourceBuilder()
                                        .seqNoAndPrimaryTerm(true)
                                        .version(true)
                                        .query(detectorsReferencingRuleQuery(nestedRulesField, ruleId))
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
                                listener.onResponse(null);
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
                                    detectors.add(Detector.docParse(xcp, hit.getId(), hit.getVersion()));
                                } catch (Exception e) {
                                    log.error(
                                            "Failed to parse detector [{}] while syncing rule [{}]",
                                            hit.getId(),
                                            ruleId,
                                            e);
                                }
                            }

                            if (detectors.isEmpty()) {
                                listener.onResponse(null);
                                return;
                            }

                            AtomicInteger remaining = new AtomicInteger(detectors.size());
                            for (Detector detector : detectors) {
                                rebuildOneAtATime(
                                        client,
                                        detector,
                                        refreshPolicy,
                                        ruleId,
                                        () -> {
                                            if (remaining.decrementAndGet() == 0) {
                                                listener.onResponse(null);
                                            }
                                        });
                            }
                        },
                        e -> {
                            // Best-effort: a failed detector lookup must not break the rule write.
                            log.error("Failed to search detectors referencing rule [{}]", ruleId, e);
                            listener.onResponse(null);
                        }));
    }

    /**
     * Rebuilds one detector, unless a rebuild of it is already in flight. In that case the rebuild is
     * marked as owed, so one more pass runs when the current one finishes, and {@code onDone} is
     * called straight away: the pass that is already running, or the one now owed, recompiles the
     * detector from the rules as they stand, which covers this rule as well.
     */
    // Package-private so the coalescing can be driven directly from the tests: reaching it through
    // rebuildDetectorsForRule would mean building a detectors search response for every case.
    static void rebuildOneAtATime(
            Client client,
            Detector detector,
            WriteRequest.RefreshPolicy refreshPolicy,
            String ruleId,
            Runnable onDone) {
        String detectorId = detector.getId();
        if (REBUILDS_IN_FLIGHT.putIfAbsent(detectorId, Boolean.FALSE) != null) {
            REBUILDS_IN_FLIGHT.put(detectorId, Boolean.TRUE);
            log.debug(
                    "Rebuild of detector [{}] already in flight; coalescing the one owed by rule [{}]",
                    detectorId,
                    ruleId);
            onDone.run();
            return;
        }
        issueRebuild(client, detector, refreshPolicy, ruleId, onDone);
    }

    /** Issues the detector re-index and, when it completes, runs the pass owed meanwhile, if any. */
    private static void issueRebuild(
            Client client,
            Detector detector,
            WriteRequest.RefreshPolicy refreshPolicy,
            String ruleId,
            Runnable onDone) {
        IndexDetectorRequest indexRequest =
                new IndexDetectorRequest(detector.getId(), refreshPolicy, RestRequest.Method.PUT, detector);
        client.execute(
                IndexDetectorAction.INSTANCE,
                indexRequest,
                ActionListener.wrap(
                        r -> {
                            log.debug(
                                    "Rebuilt detector [{}] after change to rule [{}]", detector.getId(), ruleId);
                            completeRebuild(client, detector, refreshPolicy, ruleId, onDone);
                        },
                        e -> {
                            log.error(
                                    "Failed to rebuild detector [{}] after change to rule [{}]",
                                    detector.getId(),
                                    ruleId,
                                    e);
                            completeRebuild(client, detector, refreshPolicy, ruleId, onDone);
                        }));
    }

    /**
     * Releases the detector, or keeps it and runs the owed pass. The check and the release are one
     * atomic operation, so a rebuild asked for while this one was completing is not lost.
     */
    private static void completeRebuild(
            Client client,
            Detector detector,
            WriteRequest.RefreshPolicy refreshPolicy,
            String ruleId,
            Runnable onDone) {
        Boolean owed =
                REBUILDS_IN_FLIGHT.compute(
                        detector.getId(), (id, pending) -> Boolean.TRUE.equals(pending) ? Boolean.FALSE : null);
        if (owed != null) {
            log.debug("Running the rebuild owed for detector [{}]", detector.getId());
            issueRebuild(client, detector, refreshPolicy, ruleId, onDone);
            return;
        }
        onDone.run();
    }

    /** Drops the in-flight state. For tests, which share the static map across cases. */
    static void clearInFlightRebuilds() {
        REBUILDS_IN_FLIGHT.clear();
    }
}
