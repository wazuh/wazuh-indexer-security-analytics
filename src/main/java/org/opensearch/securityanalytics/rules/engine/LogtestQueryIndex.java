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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Owns the percolator index logtest evaluates rules against.
 *
 * <p>One index per log type, named by {@link DetectorMonitorConfig#getLogtestRuleIndex(String)} so
 * it inherits the analysis settings of a detector's query index. Its field mappings are copied from
 * the same source indices the detector for that integration reads, because the percolator parses a
 * stored query with {@code allowUnmappedFields = false}: a compiled Sigma query naming a field the
 * index does not map is rejected outright. Copying the real mappings is therefore what makes a
 * logtest result predictive of a finding.
 *
 * <p>Materialized mappings alone are not enough, and this is the difference between logtest and
 * alerting. The WCS event templates are {@code dynamic: strict_allow_templates}: a field is
 * declared by a dynamic template and only becomes a real mapping once a document carrying it is
 * indexed. A doc-level monitor runs *after* ingestion, so by the time it copies mappings the fields
 * exist. logtest runs *before* — that is its whole purpose — so on any integration whose events
 * have not been ingested yet, every field would be missing and every rule would be rejected. That
 * is not what a detector would do: the same event, once ingested, materializes the field through
 * its dynamic template and the rule matches.
 *
 * <p>So the fields a rule needs are resolved against the source indices' {@code dynamic_templates}
 * when they are absent from {@code properties}. A field declared nowhere stays unmapped, and only
 * then is a rejection genuinely predictive of a detector finding nothing.
 *
 * <p>Unlike a detector's query index, this one is not shared between monitors, so field names are
 * copied verbatim: none of alerting's {@code <field>_<sourceIndex>_<monitorId>} suffixing applies.
 */
public class LogtestQueryIndex {

    private static final Logger log = LogManager.getLogger(LogtestQueryIndex.class);

    /** Percolator field holding the compiled Sigma query. */
    public static final String QUERY_FIELD = "query";

    /** Scopes stored queries to the integration that owns the rules. */
    public static final String INTEGRATION_ID_FIELD = "integration_id";

    /** Rule the stored query was compiled from. */
    public static final String RULE_ID_FIELD = "rule_id";

    /**
     * The fields this index needs for itself. A source index that maps a field of the same name would
     * have it silently replaced by the control mapping, and every rule referencing that field would
     * then be rejected — reported as though the source mapping were at fault.
     */
    private static final Set<String> CONTROL_FIELDS =
            Set.of(QUERY_FIELD, INTEGRATION_ID_FIELD, RULE_ID_FIELD);

    private static final String PROPERTIES = "properties";
    private static final String TYPE = "type";
    private static final String NESTED = "nested";

    /** Mapping type of a field that holds other fields. */
    private static final String OBJECT = "object";

    /** Mapping key holding an index's dynamic templates. */
    private static final String DYNAMIC_TEMPLATES = "dynamic_templates";

    /**
     * Alerting's percolator field type, not the core one: the query index is read by the same
     * percolator implementation the doc-level monitors use.
     */
    private static final String PERCOLATOR_TYPE = "percolator_ext";

    /**
     * Comfortably above the 1000-field limit the WCS event templates set, so copying a fully
     * materialized source mapping cannot breach it.
     */
    private static final int TOTAL_FIELDS_LIMIT = 10000;

    /** Characters not allowed in an index name are replaced by this one. */
    private static final String NAME_REPLACEMENT = "_";

    private final Client client;
    private final ClusterService clusterService;
    private final RuleTopicIndices ruleTopicIndices;

    /**
     * @param client the OpenSearch client.
     * @param clusterService used to test for the index without a round trip.
     * @param ruleTopicIndices owner of the query index template this index inherits its analysis
     *     settings from.
     */
    public LogtestQueryIndex(
            Client client, ClusterService clusterService, RuleTopicIndices ruleTopicIndices) {
        this.client = client;
        this.clusterService = clusterService;
        this.ruleTopicIndices = ruleTopicIndices;
    }

    /**
     * Resolves the logtest percolator index name for a log type.
     *
     * <p>Log types come from an integration title and may contain characters an index name cannot, so
     * anything outside {@code [a-z0-9_.-]} is replaced.
     *
     * @param logType the integration's log type.
     * @return the index name.
     */
    public static String indexName(String logType) {
        String sanitized =
                logType.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_.-]", NAME_REPLACEMENT);
        return DetectorMonitorConfig.getLogtestRuleIndex(sanitized);
    }

    /**
     * Creates the percolator index for the log type if needed, and makes sure its mappings cover the
     * source indices' fields.
     *
     * @param logType the integration's log type, naming the index.
     * @param sourceIndices the source indices whose field mappings the queries resolve against.
     * @param listener notified with the prepared index once it is ready to hold queries, or with a
     *     failure carrying a message fit to show as a skip reason.
     */
    public void ensureIndex(
            String logType,
            List<String> sourceIndices,
            Set<String> requiredFields,
            ActionListener<PreparedIndex> listener) {
        // The template carries rule_analyzer and rule_ws_normalizer, and it is otherwise only
        // installed when a detector is created. Nothing guarantees that has happened: logtest is
        // mostly used in the test space, which has no detector at all. Without the template the index
        // would be created without the analyzers and every query over a keyword field would be
        // rejected as "normalizer not found".
        if (ruleTopicIndices.ruleTopicIndexTemplateExists()) {
            collectMappingsAndPrepare(logType, sourceIndices, requiredFields, listener);
            return;
        }
        // Installing the template is all that is needed, and all that is allowed: this runs on a
        // user-facing endpoint, so it must not touch indices a detector owns.
        try {
            ruleTopicIndices.initRuleTopicIndexTemplate(
                    ActionListener.wrap(
                            acknowledgedResponse ->
                                    collectMappingsAndPrepare(logType, sourceIndices, requiredFields, listener),
                            listener::onFailure));
        } catch (IOException e) {
            listener.onFailure(e);
        }
    }

    /**
     * Reads the source indices' mappings and prepares the percolator index from them.
     *
     * @param logType the integration's log type, naming the index.
     * @param sourceIndices the source indices whose field mappings the queries resolve against.
     * @param listener notified with the index name.
     */
    private void collectMappingsAndPrepare(
            String logType,
            List<String> sourceIndices,
            Set<String> requiredFields,
            ActionListener<PreparedIndex> listener) {
        String indexName = indexName(logType);

        GetMappingsRequest getMappingsRequest =
                new GetMappingsRequest()
                        .indices(sourceIndices.toArray(new String[0]))
                        .indicesOptions(IndicesOptions.lenientExpandOpenHidden());

        client
                .admin()
                .indices()
                .getMappings(
                        getMappingsRequest,
                        ActionListener.wrap(
                                getMappingsResponse -> {
                                    Map<String, Object> properties =
                                            collectSourceProperties(getMappingsResponse, requiredFields);
                                    if (properties.isEmpty()) {
                                        listener.onFailure(
                                                SecurityAnalyticsException.wrap(
                                                        new org.opensearch.OpenSearchStatusException(
                                                                String.format(
                                                                        Locale.ROOT,
                                                                        "No field mappings found for source indices %s. Rules cannot be "
                                                                                + "evaluated until events for this integration have been "
                                                                                + "ingested; a deployed detector cannot match them either.",
                                                                        sourceIndices),
                                                                RestStatus.CONFLICT)));
                                        return;
                                    }
                                    createOrUpdate(indexName, properties, listener);
                                },
                                listener::onFailure));
    }

    /**
     * Creates the index with the percolator and source field mappings, or updates the mappings of an
     * existing one so newly materialized source fields become usable.
     *
     * @param indexName the percolator index name.
     * @param properties the source field properties to map.
     * @param listener notified with the prepared index.
     */
    private void createOrUpdate(
            String indexName, Map<String, Object> properties, ActionListener<PreparedIndex> listener) {
        Map<String, Object> mappingProperties = new HashMap<>(properties);
        for (String controlField : CONTROL_FIELDS) {
            if (mappingProperties.remove(controlField) != null) {
                log.warn(
                        "Source mapping for logtest query index [{}] declares [{}], which this index needs "
                                + "for itself; rules over that field cannot be evaluated here.",
                        indexName,
                        controlField);
            }
        }
        mappingProperties.put(QUERY_FIELD, Map.of(TYPE, PERCOLATOR_TYPE));
        mappingProperties.put(INTEGRATION_ID_FIELD, Map.of(TYPE, "keyword"));
        mappingProperties.put(RULE_ID_FIELD, Map.of(TYPE, "keyword"));

        if (clusterService.state().metadata().hasIndex(indexName)) {
            updateMappings(indexName, mappingProperties, listener);
            return;
        }

        // Analysis settings are inherited from the detector query index template; only what the
        // template does not carry is set here.
        CreateIndexRequest createIndexRequest =
                new CreateIndexRequest(indexName)
                        .mapping(Map.of(PROPERTIES, mappingProperties))
                        .settings(
                                Settings.builder()
                                        .put(IndexMetadata.SETTING_INDEX_HIDDEN, true)
                                        .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                                        .put(IndexMetadata.SETTING_AUTO_EXPAND_REPLICAS, "0-1")
                                        .put("index.mapping.total_fields.limit", TOTAL_FIELDS_LIMIT)
                                        .build());

        client
                .admin()
                .indices()
                .create(
                        createIndexRequest,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(CreateIndexResponse createIndexResponse) {
                                listener.onResponse(new PreparedIndex(indexName, null));
                            }

                            @Override
                            public void onFailure(Exception e) {
                                // Two concurrent logtest requests for the same log type race here; the
                                // loser just needs the mappings brought up to date.
                                if (e instanceof ResourceAlreadyExistsException) {
                                    updateMappings(indexName, mappingProperties, listener);
                                    return;
                                }
                                listener.onFailure(e);
                            }
                        });
    }

    /**
     * Brings an existing percolator index's mappings up to date with the source indices.
     *
     * <p>A rejected update is logged and not fatal: the fields already mapped still resolve, and any
     * query that needs a missing one is reported as skipped rather than silently dropped.
     *
     * @param indexName the percolator index name.
     * @param mappingProperties the properties to merge in.
     * @param listener notified with the index name.
     */
    private void updateMappings(
            String indexName,
            Map<String, Object> mappingProperties,
            ActionListener<PreparedIndex> listener) {
        client
                .admin()
                .indices()
                .putMapping(
                        new PutMappingRequest(indexName).source(Map.of(PROPERTIES, mappingProperties)),
                        ActionListener.wrap(
                                acknowledgedResponse -> listener.onResponse(new PreparedIndex(indexName, null)),
                                e -> {
                                    log.warn(
                                            "Could not update mappings of logtest query index [{}]: {}",
                                            indexName,
                                            e.getMessage());
                                    listener.onResponse(new PreparedIndex(indexName, e.getMessage()));
                                }));
    }

    /**
     * Merges the field properties of every concrete source index into one mapping tree, applying the
     * analysis overrides a detector's query index uses.
     *
     * <p>On a field mapped differently by two backing indices the first one wins. Alerting resolves
     * that by suffixing the field with the concrete index name, which only works because its compiled
     * queries are rewritten to match; logtest evaluates the query as compiled, so it maps the field
     * once and logs the conflict.
     *
     * @param getMappingsResponse mappings of the source indices.
     * @return the merged {@code properties} tree, empty when no source index has any mapping.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> collectSourceProperties(
            GetMappingsResponse getMappingsResponse, Set<String> requiredFields) {
        Map<String, Object> merged = new HashMap<>();
        List<Map<String, Object>> dynamicTemplates = new ArrayList<>();
        for (Map.Entry<String, MappingMetadata> indexMapping :
                getMappingsResponse.mappings().entrySet()) {
            if (indexMapping.getValue() == null) {
                continue;
            }
            Map<String, Object> source = indexMapping.getValue().sourceAsMap();
            Object properties = source.get(PROPERTIES);
            if (properties instanceof Map) {
                mergeProperties((Map<String, Object>) properties, merged, indexMapping.getKey());
            }
            Object templates = source.get(DYNAMIC_TEMPLATES);
            if (templates instanceof List) {
                for (Object entry : (List<?>) templates) {
                    if (entry instanceof Map) {
                        dynamicTemplates.add((Map<String, Object>) entry);
                    }
                }
            }
        }
        declareFieldsFromDynamicTemplates(merged, requiredFields, dynamicTemplates);
        applyAnalysisOverrides(merged);
        return merged;
    }

    /**
     * Adds an explicit mapping for every required field that the source indices declare through a
     * dynamic template but have not materialized yet.
     *
     * <p>Without this, logtest is unusable on any integration whose events have not been ingested:
     * the percolator refuses a query over an unmapped field, so every rule is reported as skipped
     * even though the same event, once ingested, would materialize the field and match.
     *
     * @param merged the mapping tree being built, modified in place.
     * @param requiredFields the fields the compiled rule queries name.
     * @param dynamicTemplates the source indices' dynamic templates, in the order they were read.
     */
    @SuppressWarnings("unchecked")
    static void declareFieldsFromDynamicTemplates(
            Map<String, Object> merged,
            Set<String> requiredFields,
            List<Map<String, Object>> dynamicTemplates) {
        if (requiredFields == null || requiredFields.isEmpty() || dynamicTemplates.isEmpty()) {
            return;
        }
        for (String field : requiredFields) {
            if (field == null || field.isEmpty() || isMapped(merged, field)) {
                continue;
            }
            Map<String, Object> mapping = findDynamicMapping(field, dynamicTemplates);
            if (mapping == null) {
                // Declared nowhere. Left unmapped on purpose: the percolator will refuse the query,
                // and that refusal is then a true statement about what a detector can match.
                log.debug("Field [{}] is not declared by any source index; leaving it unmapped", field);
                continue;
            }
            declareField(merged, field, mapping);
        }
    }

    /**
     * Tells whether a dotted field path already has a mapping in the tree.
     *
     * @param properties the mapping tree.
     * @param field the dotted field path.
     * @return {@code true} when the leaf exists.
     */
    @SuppressWarnings("unchecked")
    static boolean isMapped(Map<String, Object> properties, String field) {
        Map<String, Object> current = properties;
        String[] parts = field.split("\\.");
        for (int i = 0; i < parts.length; i++) {
            Object node = current.get(parts[i]);
            if (!(node instanceof Map)) {
                return false;
            }
            Map<String, Object> nodeMap = (Map<String, Object>) node;
            if (i == parts.length - 1) {
                return true;
            }
            Object children = nodeMap.get(PROPERTIES);
            if (!(children instanceof Map)) {
                return false;
            }
            current = (Map<String, Object>) children;
        }
        return false;
    }

    /**
     * Inserts a leaf mapping at a dotted field path, creating the intermediate objects.
     *
     * @param properties the mapping tree, modified in place.
     * @param field the dotted field path.
     * @param mapping the leaf mapping to place.
     */
    @SuppressWarnings("unchecked")
    static void declareField(
            Map<String, Object> properties, String field, Map<String, Object> mapping) {
        Map<String, Object> current = properties;
        String[] parts = field.split("\\.");
        for (int i = 0; i < parts.length - 1; i++) {
            Object node = current.get(parts[i]);
            if (!(node instanceof Map)) {
                Map<String, Object> created = new HashMap<>();
                created.put(PROPERTIES, new HashMap<String, Object>());
                current.put(parts[i], created);
                node = created;
            }
            Map<String, Object> nodeMap = (Map<String, Object>) node;
            Object children = nodeMap.get(PROPERTIES);
            if (!(children instanceof Map)) {
                Object type = nodeMap.get(TYPE);
                if (type != null && !OBJECT.equals(type) && !NESTED.equals(type)) {
                    // A real leaf where an object is needed: the source disagrees with the rule, so
                    // stop rather than rewrite a mapping the source owns.
                    return;
                }
                // An object with no children of its own. OpenSearch renders those as
                // {"type": "object"} with no `properties` key, which is exactly what a WCS container
                // looks like before any event has populated it — so give it the map it lacks rather
                // than mistaking it for a leaf.
                Map<String, Object> created = new HashMap<>();
                nodeMap.put(PROPERTIES, created);
                children = created;
            }
            current = (Map<String, Object>) children;
        }
        current.put(parts[parts.length - 1], new HashMap<>(mapping));
    }

    /**
     * Finds the mapping a dynamic template declares for a field, matching on {@code path_match}.
     *
     * <p>The first template whose pattern matches wins, which is how OpenSearch resolves them too.
     * Only {@code path_match} is considered: a Sigma rule names a full field path, so {@code
     * match_mapping_type} (which depends on the value being indexed) cannot be evaluated here.
     *
     * @param field the dotted field path.
     * @param dynamicTemplates the templates to search.
     * @return the declared leaf mapping, or {@code null} when nothing declares the field.
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> findDynamicMapping(
            String field, List<Map<String, Object>> dynamicTemplates) {
        for (Map<String, Object> template : dynamicTemplates) {
            for (Object body : template.values()) {
                if (!(body instanceof Map)) {
                    continue;
                }
                Map<String, Object> definition = (Map<String, Object>) body;
                Object pathMatch = definition.get("path_match");
                Object mapping = definition.get("mapping");
                if (!(mapping instanceof Map) || pathMatch == null) {
                    continue;
                }
                List<Object> patterns =
                        pathMatch instanceof List ? (List<Object>) pathMatch : List.of(pathMatch);
                for (Object pattern : patterns) {
                    if (pattern != null && pathMatches(pattern.toString(), field)) {
                        return (Map<String, Object>) mapping;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Matches a dynamic template's {@code path_match} pattern against a dotted field path.
     *
     * @param pattern the pattern, where {@code *} matches within one path segment.
     * @param field the dotted field path.
     * @return {@code true} on a match.
     */
    static boolean pathMatches(String pattern, String field) {
        if (pattern.indexOf('*') < 0) {
            return pattern.equals(field);
        }
        StringBuilder regex = new StringBuilder(pattern.length() + 16);
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '*') {
                regex.append("[^.]*");
            } else {
                regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return field.matches(regex.toString());
    }

    /**
     * Deep-merges one mapping subtree into another, keeping the fields already present.
     *
     * @param source the subtree to merge in.
     * @param target the accumulator.
     * @param sourceIndex the index the subtree came from, for conflict logging.
     */
    @SuppressWarnings("unchecked")
    static void mergeProperties(
            Map<String, Object> source, Map<String, Object> target, String sourceIndex) {
        for (Map.Entry<String, Object> field : source.entrySet()) {
            if (!(field.getValue() instanceof Map)) {
                continue;
            }
            Map<String, Object> sourceProps = (Map<String, Object>) field.getValue();
            Object existing = target.get(field.getKey());

            if (existing == null) {
                target.put(field.getKey(), deepCopy(sourceProps));
                continue;
            }

            Map<String, Object> targetProps = (Map<String, Object>) existing;
            if (sourceProps.get(PROPERTIES) instanceof Map
                    && targetProps.get(PROPERTIES) instanceof Map) {
                mergeProperties(
                        (Map<String, Object>) sourceProps.get(PROPERTIES),
                        (Map<String, Object>) targetProps.get(PROPERTIES),
                        sourceIndex);
            } else if (!targetProps.equals(sourceProps)) {
                log.debug(
                        "Field [{}] is mapped differently in [{}]; keeping the first mapping seen",
                        field.getKey(),
                        sourceIndex);
            }
        }
    }

    /**
     * Walks a mapping tree and merges {@link DetectorMonitorConfig#getRuleIndexMappingsByType()} into
     * every leaf whose type has an override, which is what attaches {@code rule_analyzer} / {@code
     * rule_ws_normalizer} — and with them whatever comparison semantics a detector's query index
     * applies — to the copied fields.
     *
     * @param properties the mapping subtree to rewrite in place.
     */
    @SuppressWarnings("unchecked")
    static void applyAnalysisOverrides(Map<String, Object> properties) {
        Map<String, Map<String, String>> overridesByType =
                DetectorMonitorConfig.getRuleIndexMappingsByType();

        for (Object value : properties.values()) {
            if (!(value instanceof Map)) {
                continue;
            }
            Map<String, Object> fieldProps = (Map<String, Object>) value;
            Object type = fieldProps.get(TYPE);

            if (type != null && !NESTED.equals(type)) {
                Map<String, String> overrides = overridesByType.get(type.toString());
                if (overrides != null) {
                    fieldProps.putAll(overrides);
                }
            }
            if (fieldProps.get(PROPERTIES) instanceof Map) {
                applyAnalysisOverrides((Map<String, Object>) fieldProps.get(PROPERTIES));
            }
        }
    }

    /**
     * An index ready to hold percolator queries.
     *
     * @param indexName the percolator index.
     * @param mappingFailure why the index's mappings could not be brought up to date, or {@code null}
     *     when they are current. A non-null value means a query rejected by the percolator may be the
     *     fault of this index rather than of the source mapping, and must not be reported as "no
     *     detector could match it either".
     */
    public record PreparedIndex(String indexName, String mappingFailure) {}

    /**
     * Copies a mapping subtree so the merged tree can be rewritten without touching cluster state.
     *
     * @param source the subtree to copy.
     * @return a mutable deep copy.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> deepCopy(Map<String, Object> source) {
        Map<String, Object> copy = new HashMap<>();
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            if (entry.getValue() instanceof Map) {
                copy.put(entry.getKey(), deepCopy((Map<String, Object>) entry.getValue()));
            } else {
                copy.put(entry.getKey(), entry.getValue());
            }
        }
        return copy;
    }
}
