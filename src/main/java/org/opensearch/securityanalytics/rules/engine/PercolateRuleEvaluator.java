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
package org.opensearch.securityanalytics.rules.engine;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequestBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionNOT;
import org.opensearch.securityanalytics.rules.condition.ConditionType;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.objects.SigmaCondition;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.rules.types.SigmaCIDRExpression;
import org.opensearch.securityanalytics.rules.types.SigmaCompareExpression;
import org.opensearch.securityanalytics.rules.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.transport.client.Client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Evaluates Sigma rules against one normalized event the way a deployed detector does: the rules
 * are compiled with {@link OSQueryBackend}, stored in a percolator index that carries a detector
 * query index's analysis settings, and the event is percolated against them.
 *
 * <p>This exists because matching a rule in the JVM and matching it through the percolator are not
 * the same operation. Compiled queries go through {@code query_string} parsing, the query index's
 * analyzers and the percolator's own field-mapping requirements, none of which an interpreter
 * reproduces. Anything that stops a rule from matching in production — an unmapped field, a value
 * the compiler cannot express, case — therefore shows up here too, which is the whole point of
 * logtest.
 */
public class PercolateRuleEvaluator {

    private static final Logger log = LogManager.getLogger(PercolateRuleEvaluator.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String STATUS_SUCCESS = "success";
    private static final String UNKNOWN_VALUE = "unknown";

    /** Digest used to derive a percolator document id from its content. */
    private static final String DOC_ID_DIGEST = "SHA-256";

    /**
     * How long a superseded query document is left alone before it can be pruned. A logtest request
     * is bounded by its own thread pool and a 1 MiB body cap and completes in well under a second, so
     * a minute is a wide margin: cleanup can never delete a document a concurrent call is still
     * percolating against, and superseded documents do not outlive an editing session by long.
     */
    private static final long SUPERSEDED_GRACE_MILLIS = 60_000L;

    private final Client client;
    private final LogtestQueryIndex queryIndex;

    /**
     * @param client the OpenSearch client.
     * @param queryIndex owner of the percolator index the queries are stored in.
     */
    public PercolateRuleEvaluator(Client client, LogtestQueryIndex queryIndex) {
        this.client = client;
        this.queryIndex = queryIndex;
    }

    /**
     * A parsed rule together with the YAML it came from.
     *
     * <p>The body is kept because describing a matched rule's conditions needs a second parse: {@code
     * SigmaCondition#parsed} drives a one-shot ANTLR parser, and compiling the rule consumes the one
     * belonging to the instance being percolated.
     *
     * @param rule the parsed rule.
     * @param body the YAML it was parsed from.
     */
    public record ParsedRule(SigmaRule rule, String body) {}

    /**
     * Compiles the rules, stores them as percolator queries and percolates the event against them.
     *
     * @param eventJson the normalized event as a JSON object string.
     * @param rules the parsed rules to evaluate, each with the YAML it came from.
     * @param integrationId the integration owning the rules; scopes the stored queries.
     * @param logType the integration's log type, naming the percolator index.
     * @param sourceIndices source indices whose mappings the compiled queries resolve against.
     * @param listener notified with the result JSON.
     */
    public void evaluate(
            String eventJson,
            List<ParsedRule> rules,
            String integrationId,
            String logType,
            List<String> sourceIndices,
            ActionListener<String> listener) {

        int rulesEvaluated = rules.size();

        // percolate_ext only accepts an object as its document, and it is not parsed until the search
        // is rewritten — by which point every compiled query has already been written to the index.
        // Fail before touching it.
        if (!isJsonObject(eventJson)) {
            listener.onFailure(
                    SecurityAnalyticsException.wrap(
                            new OpenSearchStatusException(
                                    "The normalized event must be a JSON object to be evaluated against rules.",
                                    RestStatus.BAD_REQUEST)));
            return;
        }

        // Doc id -> the rule and compiled query it holds, so a percolate hit needs no _source.
        Map<String, CompiledQuery> compiled = new LinkedHashMap<>();
        Set<String> requiredFields = new LinkedHashSet<>();
        compile(rules, integrationId, compiled, requiredFields);

        if (compiled.isEmpty()) {
            listener.onResponse(buildResult(rulesEvaluated, Collections.emptyList(), Map.of()));
            return;
        }

        queryIndex.ensureIndex(
                logType,
                sourceIndices,
                requiredFields,
                ActionListener.wrap(
                        preparedIndex ->
                                storeQueries(
                                        preparedIndex, integrationId, compiled, rulesEvaluated, eventJson, listener),
                        e -> {
                            // The percolator index could not be prepared, so nothing was evaluated. Report
                            // it as such instead of returning "no matches", which would read as "the rules
                            // do not match this event".
                            log.warn("Could not prepare the logtest query index: {}", e.getMessage());
                            listener.onFailure(e);
                        }));
    }

    /**
     * Compiles each rule the way rule upload does and keeps the one query a deployed detector would
     * actually run, recording the rules that cannot be evaluated at all.
     *
     * <p>{@code convertRule} returns one query per parsed {@code detection.condition}, but a detector
     * is built from {@code rule.getQueries().get(0)} alone ({@code
     * TransportIndexDetectorAction#createDocLevelMonitorRequest}), so only the first is stored here.
     * Percolating the others would make logtest report matches production cannot produce — the very
     * divergence this class exists to remove. That a detector ignores the remaining conditions is a
     * separate defect; it is logged, not hidden, and tracked on its own.
     *
     * @param rules the parsed rules.
     * @param integrationId the integration owning the rules; part of the document identity.
     * @param compiled receives doc id to compiled query.
     * @param requiredFields receives every field the compiled queries name, so the query index can
     *     make sure they are mapped before the queries are stored.
     */
    private void compile(
            List<ParsedRule> rules,
            String integrationId,
            Map<String, CompiledQuery> compiled,
            Set<String> requiredFields) {
        for (int position = 0; position < rules.size(); position++) {
            SigmaRule rule = rules.get(position).rule();
            String body = rules.get(position).body();
            String ruleId = ruleId(rule, position);
            try {
                // Constructed exactly as WTransportIndexRuleAction:225 does when a rule is uploaded —
                // same arguments, so the compiled query is the same one a detector would run. One
                // backend per rule, so a rule cannot inherit state collected while converting another.
                QueryBackend backend = new OSQueryBackend(Collections.emptyMap(), false);
                List<Object> queries = backend.convertRule(rule);

                if (queries.isEmpty()) {
                    log.warn("Rule '{}' has no detection condition to match", ruleId);
                    continue;
                }
                if (queries.stream().anyMatch(query -> !(query instanceof String))) {
                    // Aggregation rules become bucket-level monitors, which count documents over a
                    // window. A single event cannot satisfy one, and percolation cannot express it.
                    log.warn(
                            "Rule '{}' aggregates over several events, which a percolator cannot evaluate "
                                    + "against a single document",
                            ruleId);
                    continue;
                }

                if (queries.size() > 1) {
                    log.warn(
                            "Rule '{}' has {} detection conditions, but a deployed detector evaluates only "
                                    + "the first; logtest matches that behaviour and ignores the other {}.",
                            ruleId,
                            queries.size(),
                            queries.size() - 1);
                }

                String query = queries.get(0).toString();
                // The percolator parses a stored query with unmapped fields disallowed, so the index
                // has to be told which fields to make sure of. This is the same field set rule upload
                // records as the rule's query_field_names.
                requiredFields.addAll(backend.getQueryFields().keySet());
                compiled.put(
                        docId(integrationId, ruleId, query), new CompiledQuery(rule, ruleId, query, body));
            } catch (Exception e) {
                log.warn("Rule '{}' could not be compiled: {}", ruleId, e.getMessage());
            }
        }
    }

    /**
     * Upserts the compiled queries into the percolator index, then percolates.
     *
     * <p>Doc ids are content-addressed, so re-running logtest on an unchanged rule is a no-op, while
     * an edited rule stores a new document and leaves the previous one behind. Those superseded
     * documents are removed after the search — see {@link #deleteSupersededQueries}. The refresh is
     * immediate because the percolate search runs right after.
     *
     * @param indexName the percolator index.
     * @param integrationId scopes the stored queries.
     * @param compiled doc id to compiled query.
     * @param rulesEvaluated number of rules the request covered.
     * @param eventJson the event to percolate.
     * @param listener notified with the result JSON.
     */
    private void storeQueries(
            LogtestQueryIndex.PreparedIndex preparedIndex,
            String integrationId,
            Map<String, CompiledQuery> compiled,
            int rulesEvaluated,
            String eventJson,
            ActionListener<String> listener) {

        String indexName = preparedIndex.indexName();
        BulkRequest bulkRequest =
                new BulkRequest().setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        for (Map.Entry<String, CompiledQuery> entry : compiled.entrySet()) {
            bulkRequest.add(
                    queryDocument(
                            indexName,
                            entry.getKey(),
                            entry.getValue().query(),
                            integrationId,
                            entry.getValue().ruleId()));
        }

        client.bulk(
                bulkRequest,
                ActionListener.wrap(
                        bulkResponse -> {
                            Set<String> storedDocIds = new LinkedHashSet<>(compiled.keySet());
                            collectRejectedQueries(
                                    bulkResponse, compiled, storedDocIds, preparedIndex.mappingFailure());

                            if (storedDocIds.isEmpty()) {
                                listener.onResponse(buildResult(rulesEvaluated, Collections.emptyList(), Map.of()));
                                return;
                            }
                            percolate(
                                    indexName,
                                    integrationId,
                                    eventJson,
                                    compiled,
                                    storedDocIds,
                                    rulesEvaluated,
                                    listener);
                        },
                        listener::onFailure));
    }

    /**
     * Builds the percolator document that holds one compiled query.
     *
     * @param indexName the percolator index.
     * @param docId the content-addressed document id.
     * @param query the compiled query.
     * @param integrationId the integration the query belongs to.
     * @param ruleId the rule the query belongs to.
     * @return the index request.
     */
    private IndexRequest queryDocument(
            String indexName, String docId, String query, String integrationId, String ruleId) {
        return new IndexRequest(indexName)
                .id(docId)
                // Doc ids are content-addressed, so an existing document is byte-identical and
                // re-indexing it would re-parse the query and re-extract its terms for nothing.
                // CREATE turns that into a cheap conflict, handled as success.
                .opType(DocWriteRequest.OpType.CREATE)
                .source(
                        Map.of(
                                LogtestQueryIndex.QUERY_FIELD,
                                Map.of("query_string", Map.of("query", query)),
                                LogtestQueryIndex.INTEGRATION_ID_FIELD,
                                integrationId,
                                LogtestQueryIndex.RULE_ID_FIELD,
                                ruleId,
                                LogtestQueryIndex.STORED_AT_FIELD,
                                System.currentTimeMillis()));
    }

    /**
     * Builds the percolate search that asks which of a set of stored queries the event satisfies.
     *
     * @param integrationId the integration owning the queries.
     * @param percolateQuery the {@code percolate_ext} query carrying the event.
     * @param docIds the documents to consider; the search is scoped to exactly these.
     * @return the search source.
     */
    private SearchSourceBuilder percolateSearch(
            String integrationId, String percolateQuery, Set<String> docIds) {
        return new SearchSourceBuilder()
                .query(
                        QueryBuilders.boolQuery()
                                .must(
                                        QueryBuilders.termQuery(LogtestQueryIndex.INTEGRATION_ID_FIELD, integrationId))
                                // Restrict the search to the documents this request stored. The index
                                // outlives a single call, so without this the queries of every earlier
                                // call for this integration are eligible too: they would consume the size
                                // budget below — scores are effectively tied, so the tie-break by
                                // ascending doc id favours the older segments — and each such hit resolves
                                // to nothing in the caller's map and is dropped, which reports a matching
                                // rule as not matching.
                                .filter(QueryBuilders.idsQuery().addIds(docIds.toArray(new String[0])))
                                .filter(QueryBuilders.wrapperQuery(percolateQuery)))
                // Every stored query may match, and an unset size would silently cap the result at the
                // default 10 — which is what a deployed detector's fan-out does.
                .size(docIds.size())
                .fetchSource(false);
    }

    /**
     * Turns the bulk failures into skip reasons.
     *
     * <p>A rejected query is the interesting case: the percolator parses a stored query with unmapped
     * fields disallowed, so a rule naming a field the source mapping does not have is refused here —
     * and would never produce a finding in production either. Reporting it beats leaving it out of
     * the results, which reads as "did not match".
     *
     * @param bulkResponse the bulk result.
     * @param compiled doc id to compiled query.
     * @param storedDocIds the doc ids that made it in; rejected ones are removed.
     * @param mappingFailure why the index's mappings are not current, or {@code null}.
     */
    private void collectRejectedQueries(
            BulkResponse bulkResponse,
            Map<String, CompiledQuery> compiled,
            Set<String> storedDocIds,
            String mappingFailure) {
        Set<String> reportedRuleIds = new LinkedHashSet<>();

        for (BulkItemResponse itemResponse : bulkResponse) {
            if (!itemResponse.isFailed()) {
                continue;
            }
            if (itemResponse.getFailure() != null
                    && itemResponse.getFailure().getStatus() == RestStatus.CONFLICT) {
                // The document is already there, and because ids are content-addressed it is the
                // document we were about to write. Keep it in the search scope.
                continue;
            }
            storedDocIds.remove(itemResponse.getId());
            CompiledQuery query = compiled.get(itemResponse.getId());
            if (query == null || !reportedRuleIds.add(query.ruleId())) {
                continue;
            }
            String cause = rejectionCause(itemResponse);
            RestStatus status =
                    itemResponse.getFailure() == null ? null : itemResponse.getFailure().getStatus();
            log.warn(
                    "Rule '{}' was not evaluated: {}",
                    query.ruleId(),
                    rejectionReason(cause, mappingFailure, status));
        }
    }

    /**
     * Explains a percolator rejection without over-claiming.
     *
     * <p>Saying "a detector cannot match this either" is only honest when the percolator actually
     * read the query and refused it, which it reports as {@link RestStatus#BAD_REQUEST}. Anything
     * else — a write block, a closed index, a node-level failure — means the query never got that
     * far, and the fault is logtest's own: the detector's query index is a different index with its
     * own mappings and may well match the rule. A stale mapping on this index says the same thing.
     *
     * @param cause the percolator's failure message.
     * @param mappingFailure why this index's mappings are not current, or {@code null}.
     * @param status the status the bulk item failed with, or {@code null} when unknown.
     * @return a reason fit to show to whoever called logtest.
     */
    private String rejectionReason(String cause, String mappingFailure, RestStatus status) {
        if (status != RestStatus.BAD_REQUEST) {
            return String.format(
                    Locale.ROOT,
                    "the compiled query could not be stored, so the rule was not evaluated: %s. The "
                            + "logtest query index was not usable, which is a limitation of logtest rather "
                            + "than of the rule; a deployed detector may still match it.",
                    cause);
        }
        if (mappingFailure != null) {
            return String.format(
                    Locale.ROOT,
                    "the compiled query was rejected by the percolator: %s. The logtest query index could "
                            + "not be brought up to date (%s), so this may be a limitation of logtest rather "
                            + "than of the rule; a deployed detector may still match it.",
                    cause,
                    mappingFailure);
        }
        return String.format(
                Locale.ROOT,
                "the compiled query was rejected by the percolator. Fields the source indices declare "
                        + "are mapped before the query is stored, including ones no event has "
                        + "materialized yet, so this means the rule names something those indices do not "
                        + "declare at all — a deployed detector cannot match it either: %s",
                cause);
    }

    /**
     * Extracts a message that says why the percolator refused a query.
     *
     * <p>The top-level cause is usually just "failed to parse"; what a rule author can act on — the
     * field or the value the query could not express — is in the root cause.
     *
     * @param itemResponse the failed bulk item.
     * @return the failure message, root cause included.
     */
    private String rejectionCause(BulkItemResponse itemResponse) {
        if (itemResponse.getFailure() == null) {
            return itemResponse.getFailureMessage();
        }
        Throwable cause = itemResponse.getFailure().getCause();
        if (cause == null) {
            return itemResponse.getFailureMessage();
        }
        Throwable root = cause;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        if (root == cause || root.getMessage() == null) {
            return cause.getMessage();
        }
        return cause.getMessage() + ": " + root.getMessage();
    }

    /**
     * Percolates the event against the stored queries of this integration.
     *
     * @param indexName the percolator index.
     * @param integrationId scopes the stored queries.
     * @param eventJson the event to percolate.
     * @param compiled doc id to compiled query, used to resolve hits without fetching sources.
     * @param storedDocIds the doc ids actually stored, sizing the search.
     * @param rulesEvaluated number of rules the request covered.
     * @param listener notified with the result JSON.
     */
    private void percolate(
            String indexName,
            String integrationId,
            String eventJson,
            Map<String, CompiledQuery> compiled,
            Set<String> storedDocIds,
            int rulesEvaluated,
            ActionListener<String> listener) {

        String percolateQuery;
        try {
            percolateQuery = percolateQuery(eventJson);
        } catch (Exception e) {
            listener.onFailure(e);
            return;
        }

        client.search(
                new SearchRequest(indexName)
                        .source(percolateSearch(integrationId, percolateQuery, storedDocIds))
                        .preference(Preference.PRIMARY_FIRST.type()),
                ActionListener.wrap(
                        searchResponse -> {
                            List<CompiledQuery> matches = new ArrayList<>();
                            Set<String> reportedRules = new LinkedHashSet<>();
                            for (SearchHit hit : searchResponse.getHits()) {
                                CompiledQuery query = compiled.get(hit.getId());
                                if (query == null) {
                                    continue;
                                }
                                if (reportedRules.add(query.ruleId())) {
                                    matches.add(query);
                                }
                            }
                            explainMatches(
                                    indexName,
                                    integrationId,
                                    eventJson,
                                    matches,
                                    ActionListener.wrap(
                                            explanation -> {
                                                listener.onResponse(
                                                        buildResult(rulesEvaluated, matches, explanation.conditionsByRule()));
                                                Set<String> keep = new LinkedHashSet<>(storedDocIds);
                                                keep.addAll(explanation.conditionDocIds());
                                                deleteSupersededQueries(indexName, integrationId, compiled.values(), keep);
                                            },
                                            e -> {
                                                // The rules that matched are the answer; which of their
                                                // conditions held is the detail. Losing the detail must not
                                                // lose the answer, and reporting the rule's own conditions
                                                // instead would describe the rule rather than the event.
                                                log.warn(
                                                        "Could not determine which conditions the event satisfied: {}",
                                                        e.getMessage());
                                                listener.onResponse(buildResult(rulesEvaluated, matches, Map.of()));
                                                deleteSupersededQueries(
                                                        indexName, integrationId, compiled.values(), storedDocIds);
                                            }));
                        },
                        listener::onFailure));
    }

    /**
     * Determines which conditions of the matched rules the event actually satisfies.
     *
     * <p>A percolate hit is all-or-nothing: it says the rule matched, not which part of its detection
     * did. Describing the rule's conditions instead makes the response a restatement of the rule —
     * every alternative of a value list is listed, so a rule with forty alternatives reports forty
     * conditions and two different events caught by it read identically.
     *
     * <p>So each non-negated leaf is compiled on its own, through the same {@code convertCondition}
     * call that produced the fragment inside the rule's query, stored as its own percolator document
     * and percolated against the same event. The answer comes from the engine that decided the match
     * in the first place; nothing here re-implements Sigma semantics.
     *
     * <p>Only the rules that matched are expanded, so the documents written are proportional to what
     * the response has to explain rather than to the size of the integration.
     *
     * @param indexName the percolator index.
     * @param integrationId the integration owning the rules.
     * @param eventJson the event being evaluated.
     * @param matches the rules that matched.
     * @param listener receives the conditions per rule and the documents written for them.
     */
    private void explainMatches(
            String indexName,
            String integrationId,
            String eventJson,
            List<CompiledQuery> matches,
            ActionListener<Explanation> listener) {

        Map<String, ConditionLeaf> leaves = new LinkedHashMap<>();
        for (CompiledQuery match : matches) {
            collectLeaves(match, integrationId, leaves);
        }
        if (leaves.isEmpty()) {
            listener.onResponse(new Explanation(Map.of(), Set.of()));
            return;
        }

        String percolateQuery;
        try {
            percolateQuery = percolateQuery(eventJson);
        } catch (Exception e) {
            listener.onFailure(e);
            return;
        }

        BulkRequest bulkRequest =
                new BulkRequest().setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        for (Map.Entry<String, ConditionLeaf> entry : leaves.entrySet()) {
            bulkRequest.add(
                    queryDocument(
                            indexName,
                            entry.getKey(),
                            entry.getValue().query(),
                            integrationId,
                            entry.getValue().ruleId()));
        }

        client.bulk(
                bulkRequest,
                ActionListener.wrap(
                        bulkResponse -> {
                            Set<String> stored = new LinkedHashSet<>(leaves.keySet());
                            for (BulkItemResponse itemResponse : bulkResponse) {
                                if (!itemResponse.isFailed()
                                        || (itemResponse.getFailure() != null
                                                && itemResponse.getFailure().getStatus() == RestStatus.CONFLICT)) {
                                    continue;
                                }
                                // A condition the percolator will not store cannot be confirmed, so it is
                                // left out rather than claimed. The rule's own query carries the same
                                // fragment, so this is only reachable when that query was stored before the
                                // mapping it needs went missing.
                                stored.remove(itemResponse.getId());
                                ConditionLeaf leaf = leaves.get(itemResponse.getId());
                                log.debug(
                                        "Condition of rule '{}' could not be verified: {}",
                                        leaf == null ? itemResponse.getId() : leaf.ruleId(),
                                        rejectionCause(itemResponse));
                            }
                            if (stored.isEmpty()) {
                                listener.onResponse(new Explanation(Map.of(), Set.of()));
                                return;
                            }
                            client.search(
                                    new SearchRequest(indexName)
                                            .source(percolateSearch(integrationId, percolateQuery, stored))
                                            .preference(Preference.PRIMARY_FIRST.type()),
                                    ActionListener.wrap(
                                            searchResponse -> {
                                                Set<String> satisfied = new LinkedHashSet<>();
                                                for (SearchHit hit : searchResponse.getHits()) {
                                                    satisfied.add(hit.getId());
                                                }
                                                Map<String, List<String>> byRule = new LinkedHashMap<>();
                                                for (Map.Entry<String, ConditionLeaf> entry : leaves.entrySet()) {
                                                    if (!satisfied.contains(entry.getKey())) {
                                                        continue;
                                                    }
                                                    byRule
                                                            .computeIfAbsent(
                                                                    entry.getValue().ruleId(), ruleId -> new ArrayList<>())
                                                            .add(entry.getValue().description());
                                                }
                                                listener.onResponse(new Explanation(byRule, stored));
                                            },
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    /**
     * Removes the documents this integration's rules left behind on earlier calls.
     *
     * <p>Document ids are content-addressed, which is what keeps concurrent callers from overwriting
     * each other, but it also means an edited rule stores a new document rather than replacing the
     * old one. Without this the edit-and-test loop leaves one document per revision, forever.
     *
     * <p>Scoped to the rules this call evaluated, so it cannot touch another integration, and limited
     * to documents older than {@link #SUPERSEDED_GRACE_MILLIS}, so a document a concurrent request
     * has just written is never eligible — that request's own percolate search is scoped to its ids,
     * and by the time those ids age out it has long finished. Best effort: a failure only means the
     * superseded documents stay a little longer, so it is logged rather than surfaced.
     *
     * @param indexName the percolator index.
     * @param integrationId the integration whose documents to prune.
     * @param compiled the queries this call stored, naming the rules in scope.
     * @param storedDocIds the documents this call wants to keep.
     */
    private void deleteSupersededQueries(
            String indexName,
            String integrationId,
            Collection<CompiledQuery> compiled,
            Set<String> storedDocIds) {
        Set<String> ruleIds =
                compiled.stream()
                        .map(CompiledQuery::ruleId)
                        .collect(Collectors.toCollection(LinkedHashSet::new));
        if (ruleIds.isEmpty()) {
            return;
        }
        BoolQueryBuilder superseded =
                QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery(LogtestQueryIndex.INTEGRATION_ID_FIELD, integrationId))
                        .must(QueryBuilders.termsQuery(LogtestQueryIndex.RULE_ID_FIELD, ruleIds))
                        .must(
                                QueryBuilders.rangeQuery(LogtestQueryIndex.STORED_AT_FIELD)
                                        .lt(System.currentTimeMillis() - SUPERSEDED_GRACE_MILLIS))
                        .mustNot(QueryBuilders.idsQuery().addIds(storedDocIds.toArray(new String[0])));

        new DeleteByQueryRequestBuilder(client, DeleteByQueryAction.INSTANCE)
                .source(indexName)
                .filter(superseded)
                .abortOnVersionConflict(false)
                .execute(
                        ActionListener.wrap(
                                response -> {
                                    if (response.getDeleted() > 0) {
                                        log.debug(
                                                "Removed {} superseded logtest query document(s) from [{}]",
                                                response.getDeleted(),
                                                indexName);
                                    }
                                },
                                e ->
                                        log.debug(
                                                "Could not remove superseded logtest query documents from [{}]: {}",
                                                indexName,
                                                e.getMessage())));
    }

    /**
     * Builds the {@code percolate_ext} clause as raw JSON.
     *
     * <p>Raw JSON rather than {@code PercolateQueryBuilderExt}: that class ships inside the alerting
     * plugin and is not on this plugin's compile classpath, but alerting registers {@code
     * percolate_ext} cluster-wide as a query spec, so a wrapper query parses it at rewrite time.
     *
     * @param eventJson the event to percolate.
     * @return the query as a JSON string.
     * @throws Exception if the event is not a JSON object.
     */
    private String percolateQuery(String eventJson) throws Exception {
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            builder.startObject().startObject("percolate_ext");
            builder.field("field", LogtestQueryIndex.QUERY_FIELD);
            builder.rawField(
                    "document",
                    new ByteArrayInputStream(eventJson.getBytes(StandardCharsets.UTF_8)),
                    XContentType.JSON);
            builder.endObject().endObject();
            return builder.toString();
        }
    }

    /**
     * Renders the evaluation result.
     *
     * <p>{@code matched_conditions} describes the matched rule's detection conditions, one entry per
     * condition, as the response contract requires. Percolation is all-or-nothing per query, so there
     * is no per-condition explanation to give; the query that matched is both the closest equivalent
     * and the exact expression a detector runs.
     *
     * @param rulesEvaluated number of rules the request covered.
     * @param matches the matched rules, one entry per rule.
     * @return the result as a JSON string.
     */
    private String buildResult(
            int rulesEvaluated, List<CompiledQuery> matches, Map<String, List<String>> conditionsByRule) {

        List<Map<String, Object>> matchEntries = new ArrayList<>();
        for (CompiledQuery match : matches) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("rule", ruleInfo(match.rule(), match.ruleId()));
            entry.put(
                    "matched_conditions",
                    conditionsByRule.getOrDefault(match.ruleId(), Collections.emptyList()));
            matchEntries.add(entry);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", STATUS_SUCCESS);
        result.put("rules_evaluated", rulesEvaluated);
        result.put("rules_matched", matchEntries.size());
        result.put("matches", matchEntries);

        try {
            return MAPPER.writeValueAsString(result);
        } catch (Exception e) {
            log.error("Failed to serialize the logtest evaluation result", e);
            return String.format(
                    Locale.ROOT,
                    "{\"status\":\"error\",\"rules_evaluated\":%d,\"rules_matched\":0,\"matches\":[]}",
                    rulesEvaluated);
        }
    }

    /**
     * Collects the conditions of a matched rule that can be checked on their own.
     *
     * <p>The rule is parsed afresh from its body: {@code SigmaCondition#parsed} drives a one-shot
     * ANTLR parser, and compiling the rule consumed the one belonging to the instance that was
     * percolated.
     *
     * <p>Only the first detection condition is walked, because that is the only one a deployed
     * detector runs, and negated branches are skipped: the rule matched, so a negated branch is one
     * that did <em>not</em> hold.
     *
     * @param match the matched rule and the body it was parsed from.
     * @param integrationId the integration owning the rule; part of the document identity.
     * @param leaves receives document id to leaf, in the order the conditions appear.
     */
    private void collectLeaves(
            CompiledQuery match, String integrationId, Map<String, ConditionLeaf> leaves) {
        if (match.body() == null) {
            return;
        }
        try {
            SigmaRule described = SigmaRule.fromYaml(match.body(), true);
            List<SigmaCondition> parsed = described.getDetection().getParsedCondition();
            if (parsed == null || parsed.isEmpty()) {
                return;
            }
            collectLeaves(
                    parsed.get(0).parsed().getLeft(),
                    false,
                    match.ruleId(),
                    integrationId,
                    new ConditionBackend(),
                    leaves);
        } catch (Exception e) {
            log.debug("Could not read the conditions of rule '{}': {}", match.ruleId(), e.getMessage());
        }
    }

    /**
     * Walks a condition tree, compiling every non-negated leaf into a query of its own.
     *
     * <p>Each leaf goes through {@code convertCondition} with the same arguments {@code
     * QueryBackend#convertRule} uses for a top-level condition of that shape, so the fragment is the
     * one the rule's own query embeds — the leaf is checked exactly as the rule checks it.
     *
     * @param item the condition node.
     * @param negated whether this node sits under a {@code not}.
     * @param ruleId the rule being walked.
     * @param integrationId the integration owning the rule.
     * @param backend the compiler.
     * @param leaves the accumulator.
     */
    private void collectLeaves(
            ConditionItem item,
            boolean negated,
            String ruleId,
            String integrationId,
            QueryBackend backend,
            Map<String, ConditionLeaf> leaves) {
        if (item == null || negated) {
            return;
        }
        if (item instanceof ConditionFieldEqualsValueExpression fieldExpr) {
            addLeaf(
                    ruleId,
                    integrationId,
                    fieldExpr.getField() + " matched '" + formatSigmaValue(fieldExpr.getValue()) + "'",
                    new ConditionType(Either.right(Either.left(fieldExpr))),
                    backend,
                    leaves);
            return;
        }
        if (item instanceof ConditionValueExpression valueExpr) {
            addLeaf(
                    ruleId,
                    integrationId,
                    "keywords contains '" + valueExpr.getValue() + "'",
                    new ConditionType(Either.right(Either.right(valueExpr))),
                    backend,
                    leaves);
            return;
        }
        if (item.getArgs() == null) {
            return;
        }
        for (Either<
                        AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>,
                        String>
                arg : item.getArgs()) {
            if (arg.isLeft()) {
                collectLeaves(
                        resolveConditionItem(arg.getLeft()),
                        item instanceof ConditionNOT,
                        ruleId,
                        integrationId,
                        backend,
                        leaves);
            }
        }
    }

    /**
     * Compiles one leaf and records it under its content-addressed document id.
     *
     * <p>A leaf that will not compile is left out rather than listed unverified: the response says
     * what the event satisfied, and a condition nobody checked is not that.
     *
     * @param ruleId the rule the leaf belongs to.
     * @param integrationId the integration owning the rule.
     * @param description the leaf as the response describes it.
     * @param conditionType the leaf, wrapped the way the backend expects it.
     * @param backend the compiler.
     * @param leaves the accumulator.
     */
    private void addLeaf(
            String ruleId,
            String integrationId,
            String description,
            ConditionType conditionType,
            QueryBackend backend,
            Map<String, ConditionLeaf> leaves) {
        try {
            String query = String.valueOf(backend.convertCondition(conditionType, false, false));
            leaves.putIfAbsent(
                    docId(integrationId, ruleId, query), new ConditionLeaf(ruleId, description, query));
        } catch (Exception e) {
            log.debug(
                    "Condition '{}' of rule '{}' could not be compiled on its own: {}",
                    description,
                    ruleId,
                    e.getMessage());
        }
    }

    /**
     * Unwraps the three-way union the condition tree stores its children in.
     *
     * @param anyOneOf the child.
     * @return the condition item, or {@code null} when the union is empty.
     */
    private ConditionItem resolveConditionItem(
            AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>
                    anyOneOf) {
        if (anyOneOf.isLeft()) {
            return anyOneOf.getLeft();
        }
        if (anyOneOf.isMiddle()) {
            return anyOneOf.getMiddle();
        }
        if (anyOneOf.isRight()) {
            return anyOneOf.get();
        }
        return null;
    }

    /**
     * Renders a Sigma value the way the response contract shows it.
     *
     * @param value the parsed Sigma value.
     * @return its description.
     */
    private String formatSigmaValue(SigmaType value) {
        if (value instanceof SigmaCompareExpression cmp) {
            return cmp.getOp() + " " + cmp.getNumber();
        }
        if (value instanceof SigmaCIDRExpression cidr) {
            return "cidr:" + cidr.getCidr();
        }
        if (value instanceof SigmaRegularExpression re) {
            return "re:" + re.getRegexp();
        }
        if (value instanceof SigmaExpansion exp) {
            return "expansion(" + exp.getValues().size() + " alternatives)";
        }
        // SigmaString renders a space as the `_ws_` placeholder the compiled query carries. That is an
        // internal detail of the query pipeline and has no business in a description shown to a rule
        // author.
        return value.toString().replace("_ws_", " ");
    }

    /**
     * Describes a rule the same way the response has always described it.
     *
     * @param rule the rule, or {@code null} when it could not be parsed.
     * @param ruleId the rule id.
     * @return the rule metadata.
     */
    private Map<String, Object> ruleInfo(SigmaRule rule, String ruleId) {
        Map<String, Object> ruleInfo = new LinkedHashMap<>();
        ruleInfo.put("id", ruleId);
        if (rule == null) {
            ruleInfo.put("title", UNKNOWN_VALUE);
            ruleInfo.put("level", UNKNOWN_VALUE);
            ruleInfo.put("tags", Collections.emptyList());
            return ruleInfo;
        }
        ruleInfo.put("title", rule.getTitle() != null ? rule.getTitle() : UNKNOWN_VALUE);
        ruleInfo.put("level", rule.getLevel() != null ? rule.getLevel().toString() : UNKNOWN_VALUE);
        ruleInfo.put(
                "tags",
                rule.getTags() == null
                        ? Collections.emptyList()
                        : rule.getTags().stream()
                                .map(tag -> tag.getNamespace() + "." + tag.getName())
                                .collect(Collectors.toList()));
        return ruleInfo;
    }

    /**
     * Identifies a rule. Sigma makes {@code id} optional, so a rule without one falls back to its
     * position in the request — enough to key a percolator document and to point the caller at the
     * rule.
     *
     * @param rule the parsed rule.
     * @param position the rule's position in the request.
     * @return the rule id.
     */
    public static String ruleId(SigmaRule rule, int position) {
        if (rule != null && rule.getId() != null) {
            return rule.getId().toString();
        }
        return "rule_" + position;
    }

    /**
     * Tells whether a string is a JSON object, which is what the percolator needs as its document.
     *
     * @param json the candidate.
     * @return {@code true} when it parses as a JSON object.
     */
    private static boolean isJsonObject(String json) {
        if (json == null) {
            return false;
        }
        try {
            return MAPPER.readTree(json).isObject();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Derives a percolator document's id from what it contains.
     *
     * <p>All three parts are load-bearing.
     *
     * <ul>
     *   <li><b>The compiled query</b>, because an id built from the rule id alone is reused across
     *       calls: two callers evaluating the same rule id with different rule bodies — the ordinary
     *       edit-a-draft loop — would overwrite each other's document and then resolve the resulting
     *       hit against their own compiled map, reporting a query that did not match the event.
     *   <li><b>The rule id</b>, because distinct rules may compile to the same query. Several rules
     *       of one integration can legitimately carry identical detection, and keying on the query
     *       alone collapses them into a single document, so only one of them is ever reported as
     *       matching.
     *   <li><b>The integration id</b>, to keep two integrations that share a log type — and therefore
     *       share this index — apart.
     * </ul>
     *
     * @param integrationId the integration owning the rule.
     * @param ruleId the rule the query was compiled from.
     * @param query the compiled query.
     * @return a deterministic document id.
     */
    private static String docId(String integrationId, String ruleId, String query) {
        try {
            MessageDigest digest = MessageDigest.getInstance(DOC_ID_DIGEST);
            digest.update(integrationId.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) '|');
            digest.update(ruleId.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) '|');
            digest.update(query.getBytes(StandardCharsets.UTF_8));
            StringBuilder id = new StringBuilder(64);
            for (byte b : digest.digest()) {
                id.append(String.format(Locale.ROOT, "%02x", b));
            }
            return id.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required of every JVM; if it is genuinely absent there is nothing to fall
            // back to that would still be collision-resistant.
            throw new IllegalStateException(DOC_ID_DIGEST + " is not available", e);
        }
    }

    /**
     * A compiled percolator query and the rule it came from.
     *
     * @param rule the rule.
     * @param ruleId the rule id.
     * @param query the compiled {@code query_string} query.
     */
    private record CompiledQuery(SigmaRule rule, String ruleId, String query, String body) {}

    /**
     * A backend that can compile a single condition.
     *
     * <p>{@code convertCondition} records the fields it walks in {@code ruleQueryFields}, a map only
     * {@code convertRule} creates — so calling it on its own throws. Nothing here reads that map, but
     * it has to exist. Set up in a subclass rather than in {@code QueryBackend} itself: that class is
     * upstream code, and every edit to it has to be carried across the next fork migration.
     */
    private static final class ConditionBackend extends OSQueryBackend {
        ConditionBackend() throws IOException {
            super(Collections.emptyMap(), false);
            this.ruleQueryFields = new HashMap<>();
        }
    }

    /**
     * One condition of a rule, with the query that decides it on its own.
     *
     * @param ruleId the rule the condition belongs to.
     * @param description the condition as the response describes it.
     * @param query the compiled query for this condition alone.
     */
    private record ConditionLeaf(String ruleId, String description, String query) {}

    /**
     * What the event satisfied, per rule.
     *
     * @param conditionsByRule rule id to the descriptions of the conditions the event satisfied.
     * @param conditionDocIds the documents written to answer that, so the caller can keep them.
     */
    private record Explanation(
            Map<String, List<String>> conditionsByRule, Set<String> conditionDocIds) {}
}
