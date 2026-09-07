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
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.transport.client.Client;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
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
     * A rule that could not be evaluated, and why.
     *
     * @param rule the rule, or {@code null} when it could not even be parsed.
     * @param ruleId the rule id, for an unparseable rule the position in the request.
     * @param reason a message fit to show to whoever called logtest.
     */
    public record SkippedRule(SigmaRule rule, String ruleId, String reason) {}

    /**
     * Compiles the rules, stores them as percolator queries and percolates the event against them.
     *
     * @param eventJson the normalized event as a JSON object string.
     * @param rules the parsed rules to evaluate.
     * @param alreadySkipped rules the caller could not parse, carried into the result.
     * @param integrationId the integration owning the rules; scopes the stored queries.
     * @param logType the integration's log type, naming the percolator index.
     * @param sourceIndices source indices whose mappings the compiled queries resolve against.
     * @param listener notified with the result JSON.
     */
    public void evaluate(
            String eventJson,
            List<SigmaRule> rules,
            List<SkippedRule> alreadySkipped,
            String integrationId,
            String logType,
            List<String> sourceIndices,
            ActionListener<String> listener) {

        List<SkippedRule> skipped = new ArrayList<>(alreadySkipped);
        int rulesEvaluated = rules.size() + alreadySkipped.size();

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
        compile(rules, integrationId, compiled, skipped, requiredFields);

        if (compiled.isEmpty()) {
            listener.onResponse(
                    buildResult(rulesEvaluated, Collections.emptyList(), Collections.emptyMap(), skipped));
            return;
        }

        queryIndex.ensureIndex(
                logType,
                sourceIndices,
                requiredFields,
                ActionListener.wrap(
                        preparedIndex ->
                                storeQueries(
                                        preparedIndex,
                                        integrationId,
                                        compiled,
                                        skipped,
                                        rulesEvaluated,
                                        eventJson,
                                        listener),
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
     * TransportIndexDetectorAction#createDocLevelMonitorFromQueries}), so only the first is stored
     * here. Percolating the others would make logtest report matches production cannot produce — the
     * very divergence this class exists to remove. That a detector ignores the remaining conditions
     * is a separate defect; it is logged, not hidden, and tracked on its own.
     *
     * @param rules the parsed rules.
     * @param integrationId the integration owning the rules; part of the document identity.
     * @param compiled receives doc id to compiled query.
     * @param skipped receives the rules that cannot be evaluated.
     * @param requiredFields receives every field the compiled queries name, so the query index can
     *     make sure they are mapped before the queries are stored.
     */
    private void compile(
            List<SigmaRule> rules,
            String integrationId,
            Map<String, CompiledQuery> compiled,
            List<SkippedRule> skipped,
            Set<String> requiredFields) {
        for (int position = 0; position < rules.size(); position++) {
            SigmaRule rule = rules.get(position);
            String ruleId = ruleId(rule, position);
            try {
                // Constructed exactly as WTransportIndexRuleAction:225 does when a rule is uploaded —
                // same arguments, so the compiled query is the same one a detector would run. One
                // backend per rule, so a rule cannot inherit state collected while converting another.
                QueryBackend backend = new OSQueryBackend(Collections.emptyMap(), false);
                List<Object> queries = backend.convertRule(rule);

                if (queries.isEmpty()) {
                    skipped.add(
                            new SkippedRule(rule, ruleId, "the rule has no detection condition to match"));
                    continue;
                }
                if (queries.stream().anyMatch(query -> !(query instanceof String))) {
                    // Aggregation rules become bucket-level monitors, which count documents over a
                    // window. A single event cannot satisfy one, and percolation cannot express it.
                    skipped.add(
                            new SkippedRule(
                                    rule, ruleId, "aggregation rules cannot be evaluated against a single event"));
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
                compiled.put(docId(integrationId, ruleId, query), new CompiledQuery(rule, ruleId, query));
            } catch (Exception e) {
                log.warn("Failed to compile rule '{}': {}", ruleId, e.getMessage());
                skipped.add(
                        new SkippedRule(
                                rule, ruleId, String.format(Locale.ROOT, "the rule could not be compiled: %s", e)));
            }
        }
    }

    /**
     * Upserts the compiled queries into the percolator index, then percolates.
     *
     * <p>Doc ids are derived from the rule, so re-running logtest overwrites rather than accumulates,
     * and the index holds at most one document per rule condition. The refresh is immediate because
     * the percolate search runs right after.
     *
     * @param indexName the percolator index.
     * @param integrationId scopes the stored queries.
     * @param compiled doc id to compiled query.
     * @param skipped receives rules whose query the percolator rejected.
     * @param rulesEvaluated number of rules the request covered.
     * @param eventJson the event to percolate.
     * @param listener notified with the result JSON.
     */
    private void storeQueries(
            LogtestQueryIndex.PreparedIndex preparedIndex,
            String integrationId,
            Map<String, CompiledQuery> compiled,
            List<SkippedRule> skipped,
            int rulesEvaluated,
            String eventJson,
            ActionListener<String> listener) {

        String indexName = preparedIndex.indexName();
        BulkRequest bulkRequest =
                new BulkRequest().setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        for (Map.Entry<String, CompiledQuery> entry : compiled.entrySet()) {
            bulkRequest.add(
                    new IndexRequest(indexName)
                            .id(entry.getKey())
                            // Doc ids are content-addressed, so an existing document is byte-identical
                            // and re-indexing it would re-parse the query and re-extract its terms for
                            // nothing. CREATE turns that into a cheap conflict, handled as success.
                            .opType(DocWriteRequest.OpType.CREATE)
                            .source(
                                    Map.of(
                                            LogtestQueryIndex.QUERY_FIELD,
                                            Map.of("query_string", Map.of("query", entry.getValue().query())),
                                            LogtestQueryIndex.INTEGRATION_ID_FIELD,
                                            integrationId,
                                            LogtestQueryIndex.RULE_ID_FIELD,
                                            entry.getValue().ruleId())));
        }

        client.bulk(
                bulkRequest,
                ActionListener.wrap(
                        bulkResponse -> {
                            Set<String> storedDocIds = new LinkedHashSet<>(compiled.keySet());
                            collectRejectedQueries(
                                    bulkResponse, compiled, skipped, storedDocIds, preparedIndex.mappingFailure());

                            if (storedDocIds.isEmpty()) {
                                listener.onResponse(
                                        buildResult(
                                                rulesEvaluated, Collections.emptyList(), Collections.emptyMap(), skipped));
                                return;
                            }
                            percolate(
                                    indexName,
                                    integrationId,
                                    eventJson,
                                    compiled,
                                    storedDocIds,
                                    skipped,
                                    rulesEvaluated,
                                    listener);
                        },
                        listener::onFailure));
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
     * @param skipped receives one entry per rejected rule.
     * @param storedDocIds the doc ids that made it in; rejected ones are removed.
     * @param mappingFailure why the index's mappings are not current, or {@code null}.
     */
    private void collectRejectedQueries(
            BulkResponse bulkResponse,
            Map<String, CompiledQuery> compiled,
            List<SkippedRule> skipped,
            Set<String> storedDocIds,
            String mappingFailure) {
        Set<String> reportedRuleIds =
                skipped.stream()
                        .map(SkippedRule::ruleId)
                        .collect(Collectors.toCollection(LinkedHashSet::new));

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
            log.debug("Rule '{}' could not be stored as a percolator query: {}", query.ruleId(), cause);
            skipped.add(
                    new SkippedRule(query.rule(), query.ruleId(), rejectionReason(cause, mappingFailure)));
        }
    }

    /**
     * Explains a percolator rejection without over-claiming.
     *
     * <p>The usual cause is a rule naming a field the source index has not materialized, and then a
     * deployed detector cannot match the rule either — that is the useful thing to say. But the same
     * rejection follows from this index's own mappings being stale or in conflict, in which case
     * blaming the rule would be wrong: the detector's query index has its own mapping and may well
     * match. Only claim the former when the mappings are known to be current.
     *
     * @param cause the percolator's failure message.
     * @param mappingFailure why this index's mappings are not current, or {@code null}.
     * @return a reason fit to show to whoever called logtest.
     */
    private String rejectionReason(String cause, String mappingFailure) {
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
     * @param skipped rules that were not evaluated.
     * @param rulesEvaluated number of rules the request covered.
     * @param listener notified with the result JSON.
     */
    private void percolate(
            String indexName,
            String integrationId,
            String eventJson,
            Map<String, CompiledQuery> compiled,
            Set<String> storedDocIds,
            List<SkippedRule> skipped,
            int rulesEvaluated,
            ActionListener<String> listener) {

        String percolateQuery;
        try {
            percolateQuery = percolateQuery(eventJson);
        } catch (Exception e) {
            listener.onFailure(e);
            return;
        }

        SearchSourceBuilder searchSourceBuilder =
                new SearchSourceBuilder()
                        .query(
                                QueryBuilders.boolQuery()
                                        .must(
                                                QueryBuilders.termQuery(
                                                        LogtestQueryIndex.INTEGRATION_ID_FIELD, integrationId))
                                        // Restrict the search to the documents this request stored. The index
                                        // outlives a single call, so without this the queries of every earlier
                                        // call for this integration are eligible too: they would consume the
                                        // size budget below — scores are effectively tied, so the tie-break by
                                        // ascending doc id favours the older segments — and each such hit
                                        // resolves to nothing in `compiled` and is dropped, which reports a
                                        // matching rule as not matching.
                                        .filter(QueryBuilders.idsQuery().addIds(storedDocIds.toArray(new String[0])))
                                        .filter(QueryBuilders.wrapperQuery(percolateQuery)))
                        // Every stored query may match, and an unset size would silently cap the result
                        // at the default 10 — which is what a deployed detector's fan-out does.
                        .size(storedDocIds.size())
                        .fetchSource(false);

        client.search(
                new SearchRequest(indexName)
                        .source(searchSourceBuilder)
                        .preference(Preference.PRIMARY_FIRST.type()),
                ActionListener.wrap(
                        searchResponse -> {
                            List<CompiledQuery> matches = new ArrayList<>();
                            Map<String, List<String>> matchedQueriesByRule = new LinkedHashMap<>();
                            for (SearchHit hit : searchResponse.getHits()) {
                                CompiledQuery query = compiled.get(hit.getId());
                                if (query == null) {
                                    continue;
                                }
                                if (matchedQueriesByRule.putIfAbsent(
                                                query.ruleId(), new ArrayList<>(List.of(query.query())))
                                        == null) {
                                    matches.add(query);
                                } else {
                                    matchedQueriesByRule.get(query.ruleId()).add(query.query());
                                }
                            }
                            listener.onResponse(
                                    buildResult(rulesEvaluated, matches, matchedQueriesByRule, skipped));
                        },
                        listener::onFailure));
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
     * <p>{@code matched_conditions} carries the compiled queries that matched. Percolation is
     * all-or-nothing per query, so there is no per-condition explanation to give; the query that
     * matched is both the closest equivalent and the exact expression a detector runs.
     *
     * @param rulesEvaluated number of rules the request covered.
     * @param matches the matched rules, one entry per rule.
     * @param matchedQueriesByRule rule id to the queries that matched for it.
     * @param skipped rules that were not evaluated, and why.
     * @return the result as a JSON string.
     */
    private String buildResult(
            int rulesEvaluated,
            List<CompiledQuery> matches,
            Map<String, List<String>> matchedQueriesByRule,
            List<SkippedRule> skipped) {

        List<Map<String, Object>> matchEntries = new ArrayList<>();
        for (CompiledQuery match : matches) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("rule", ruleInfo(match.rule(), match.ruleId()));
            entry.put(
                    "matched_conditions",
                    matchedQueriesByRule.getOrDefault(match.ruleId(), List.of(match.query())));
            matchEntries.add(entry);
        }

        List<Map<String, Object>> skippedEntries = new ArrayList<>();
        for (SkippedRule skippedRule : skipped) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("rule", ruleInfo(skippedRule.rule(), skippedRule.ruleId()));
            entry.put("reason", skippedRule.reason());
            skippedEntries.add(entry);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", STATUS_SUCCESS);
        result.put("rules_evaluated", rulesEvaluated);
        result.put("rules_matched", matchEntries.size());
        result.put("matches", matchEntries);
        result.put("rules_skipped", skippedEntries.size());
        result.put("skipped", skippedEntries);

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
    private record CompiledQuery(SigmaRule rule, String ruleId, String query) {}
}
