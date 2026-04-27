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
package org.opensearch.securityanalytics.model;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend.AggregationQueries;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.objects.SigmaCondition;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.model.Detector.NO_ID;
import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class Rule implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(Rule.class);

    public static final String CATEGORY = "category";
    public static final String LOG_SOURCE = "log_source";

    public static final String TAGS = "tags";
    public static final String REFERENCES = "references";

    public static final String LEVEL = "level";
    public static final String FALSE_POSITIVES = "false_positives";

    public static final String STATUS = "status";

    private static final String QUERIES = "queries";
    public static final String QUERY_FIELD_NAMES = "query_field_names";

    public static final String RULE = "rule";

    public static final String MITRE = "mitre";
    public static final String COMPLIANCE = "compliance";
    public static final String METADATA = "metadata";

    public static final String PRE_PACKAGED_RULES_INDEX = ".opensearch-sap-pre-packaged-rules-config";
    public static final String CUSTOM_RULES_INDEX = ".opensearch-sap-custom-rules-config";
    public static final String AGGREGATION_QUERIES = "aggregationQueries";

    public static final String DOCUMENT_ID_FIELD = "document.id";

    /** Field name for the rule lifecycle space (for example, pre-packaged vs custom). */
    public static final String SPACE_FIELD = "space";

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY =
            new NamedXContentRegistry.Entry(
                    Rule.class, new ParseField(CATEGORY), xcp -> Rule.parse(xcp, null, null));

    private String id;

    private Long version;

    private final String category;

    private final String logSource;

    private final List<Value> references;

    private final List<Value> tags;

    private final String level;

    private final List<Value> falsePositives;

    private final String status;

    private final Instant date;

    private final List<Value> queries;

    private final List<Value> queryFieldNames;

    private final String rule;

    private final List<Value> aggregationQueries;

    private final Map<String, Object> mitre;

    private final Map<String, Object> complianceMap;

    private final Map<String, Object> metadata;

    private String documentId;

    private String space;

    public Rule(
            String id,
            Long version,
            String title,
            String category,
            String logSource,
            String description,
            List<Value> references,
            List<Value> tags,
            String level,
            List<Value> falsePositives,
            String author,
            String status,
            Instant date,
            List<Value> queries,
            List<Value> queryFieldNames,
            String rule,
            List<Value> aggregationQueries) {
        this(
                id,
                version,
                category,
                logSource,
                references,
                tags,
                level,
                falsePositives,
                status,
                date,
                queries,
                queryFieldNames,
                rule,
                aggregationQueries,
                Collections.emptyMap(),
                Collections.emptyMap(),
                Collections.emptyMap());
    }

    public Rule(
            String id,
            Long version,
            String category,
            String logSource,
            List<Value> references,
            List<Value> tags,
            String level,
            List<Value> falsePositives,
            String status,
            Instant date,
            List<Value> queries,
            List<Value> queryFieldNames,
            String rule,
            List<Value> aggregationQueries,
            Map<String, Object> mitre,
            Map<String, Object> complianceMap,
            Map<String, Object> metadata) {
        this.id = id != null ? id : NO_ID;
        this.version = version != null ? version : NO_VERSION;

        this.category = category;
        this.logSource = logSource;

        this.references = references;
        this.tags = tags;

        this.level = level;
        this.falsePositives = falsePositives;

        this.status = status;

        this.date = date;

        this.queries = queries;
        this.queryFieldNames = queryFieldNames;
        this.rule = rule;
        this.aggregationQueries = aggregationQueries;
        this.mitre = mitre != null ? mitre : Collections.emptyMap();
        this.complianceMap = complianceMap != null ? complianceMap : Collections.emptyMap();
        this.metadata = metadata != null ? metadata : Collections.emptyMap();
    }

    public Rule(
            String id,
            Long version,
            SigmaRule rule,
            String category,
            List<Object> queries,
            List<String> queryFieldNames,
            String original) {
        this(
                id,
                version,
                category,
                rule.getLogSource().getCategory() != null
                        ? rule.getLogSource().getCategory()
                        : (rule.getLogSource().getProduct() != null
                                ? rule.getLogSource().getProduct()
                                : rule.getLogSource().getService()),
                rule.getReferences().stream().map(Value::new).collect(Collectors.toList()),
                rule.getTags().stream()
                        .map(
                                ruleTag ->
                                        new Value(
                                                String.format(
                                                        Locale.getDefault(),
                                                        "%s.%s",
                                                        ruleTag.getNamespace(),
                                                        ruleTag.getName())))
                        .collect(Collectors.toList()),
                rule.getLevel().toString(),
                rule.getFalsePositives().stream().map(Value::new).collect(Collectors.toList()),
                rule.getStatus().toString(),
                Instant.ofEpochMilli(rule.getDate().getTime()),
                queries.stream()
                        .filter(query -> !(query instanceof AggregationQueries))
                        .map(query -> new Value(query.toString()))
                        .collect(Collectors.toList()),
                queryFieldNames.stream().map(Value::new).collect(Collectors.toList()),
                original,
                // If one of the queries is AggregationQuery -> the whole rule can be considered as Agg
                queries.stream()
                        .filter(query -> query instanceof AggregationQueries)
                        .map(it -> new Value(it.toString()))
                        .collect(Collectors.toList()),
                rule.getMitre() != null ? rule.getMitre().toMitreMap() : Collections.emptyMap(),
                rule.getCompliance() != null
                        ? rule.getCompliance().toComplianceMap()
                        : Collections.emptyMap(),
                rule.getMetadata() != null ? rule.getMetadata().toMap() : Collections.emptyMap());
    }

    @SuppressWarnings("unchecked")
    public Rule(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readString(),
                sin.readString(),
                sin.readList(Value::readFrom),
                sin.readList(Value::readFrom),
                sin.readString(),
                sin.readList(Value::readFrom),
                sin.readString(),
                sin.readInstant(),
                sin.readList(Value::readFrom),
                sin.readList(Value::readFrom),
                sin.readString(),
                sin.readList(Value::readFrom),
                (Map<String, Object>) sin.readGenericValue(), // mitre
                (Map<String, Object>) sin.readGenericValue(), // compliance
                (Map<String, Object>) sin.readGenericValue() // metadata
                );
        this.documentId = sin.readOptionalString();
        this.space = sin.readOptionalString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        out.writeLong(this.version);

        out.writeString(this.category);
        out.writeString(this.logSource);

        out.writeCollection(this.references);
        out.writeCollection(this.tags);

        out.writeString(this.level);
        out.writeCollection(this.falsePositives);

        out.writeString(this.status);
        out.writeInstant(this.date);

        out.writeCollection(this.queries);
        out.writeCollection(this.queryFieldNames);

        out.writeString(this.rule);
        out.writeCollection(this.aggregationQueries);
        out.writeGenericValue(this.mitre);
        out.writeGenericValue(this.complianceMap);
        out.writeGenericValue(this.metadata);
        out.writeOptionalString(this.documentId);
        out.writeOptionalString(this.space);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return this.createXContentBuilder(builder, params);
    }

    private XContentBuilder createXContentBuilder(XContentBuilder builder, ToXContent.Params params)
            throws IOException {
        builder.startObject();
        if (params.paramAsBoolean("with_type", false)) {
            builder.startObject("rule");
        }

        builder.field(CATEGORY, this.category).field(LOG_SOURCE, this.logSource);

        Value[] refArray = new Value[] {};
        refArray = this.references.toArray(refArray);
        builder.field(REFERENCES, refArray);

        Value[] tagArray = new Value[] {};
        tagArray = this.tags.toArray(tagArray);
        builder.field(TAGS, tagArray);

        builder.field(LEVEL, this.level);

        Value[] falsePosArray = new Value[] {};
        falsePosArray = this.falsePositives.toArray(falsePosArray);
        builder.field(FALSE_POSITIVES, falsePosArray);

        builder.field(STATUS, this.status);

        Value[] queryArray = new Value[] {};
        queryArray = this.queries.toArray(queryArray);
        builder.field(QUERIES, queryArray);
        Value[] queryFieldNamesArray = new Value[] {};
        queryFieldNamesArray = this.queryFieldNames.toArray(queryFieldNamesArray);
        builder.field(QUERY_FIELD_NAMES, queryFieldNamesArray);

        Value[] aggregationsArray = new Value[] {};
        aggregationsArray = this.aggregationQueries.toArray(aggregationsArray);
        builder.field(AGGREGATION_QUERIES, aggregationsArray);

        builder.field(RULE, this.rule);

        if (this.mitre != null && !this.mitre.isEmpty()) {
            builder.field(MITRE, this.mitre);
        }
        if (this.complianceMap != null && !this.complianceMap.isEmpty()) {
            builder.field(COMPLIANCE, this.complianceMap);
        }
        if (this.metadata != null && !this.metadata.isEmpty()) {
            builder.field(METADATA, this.metadata);
        }

        if (this.documentId != null) {
            builder.field(DOCUMENT_ID_FIELD, this.documentId);
        }
        if (this.space != null) {
            builder.field(SPACE_FIELD, this.space);
        }

        if (params.paramAsBoolean("with_type", false)) {
            builder.endObject();
        }
        return builder.endObject();
    }

    public static Rule docParse(XContentParser xcp, String id, Long version) throws IOException {
        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        Rule rule = Rule.parse(xcp, id, version);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, xcp.nextToken(), xcp);

        rule.setId(id);
        rule.setVersion(version);
        return rule;
    }

    public static Rule parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }
        if (version == null) {
            version = NO_VERSION;
        }

        String title = null;
        String category = null;
        String logSource = null;
        String description = null;

        List<Value> references = new ArrayList<>();
        List<Value> tags = new ArrayList<>();

        String level = null;
        List<Value> falsePositives = new ArrayList<>();

        String author = null;
        String status = null;
        Instant date = null;

        List<Value> queries = new ArrayList<>();
        List<Value> queryFields = new ArrayList<>();
        String original = null;
        List<Value> aggregationQueries = new ArrayList<>();
        Map<String, Object> mitre = Collections.emptyMap();
        Map<String, Object> compliance = Collections.emptyMap();
        Map<String, Object> metadata = Collections.emptyMap();
        String documentId = null;
        String space = null;

        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case CATEGORY:
                    category = xcp.text();
                    break;
                case LOG_SOURCE:
                    logSource = xcp.text();
                    break;
                case REFERENCES:
                    XContentParserUtils.ensureExpectedToken(
                            XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        references.add(Value.parse(xcp));
                    }
                    break;
                case TAGS:
                    XContentParserUtils.ensureExpectedToken(
                            XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        tags.add(Value.parse(xcp));
                    }
                    break;
                case LEVEL:
                    level = xcp.text();
                    break;
                case FALSE_POSITIVES:
                    XContentParserUtils.ensureExpectedToken(
                            XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        falsePositives.add(Value.parse(xcp));
                    }
                    break;
                case STATUS:
                    status = xcp.text();
                    break;
                case QUERIES:
                    XContentParserUtils.ensureExpectedToken(
                            XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        queries.add(Value.parse(xcp));
                    }
                    break;
                case QUERY_FIELD_NAMES:
                    XContentParserUtils.ensureExpectedToken(
                            XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        queryFields.add(Value.parse(xcp));
                    }
                    break;
                case RULE:
                    original = xcp.text();
                    break;
                case AGGREGATION_QUERIES:
                    XContentParserUtils.ensureExpectedToken(
                            XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        aggregationQueries.add(Value.parse(xcp));
                    }
                    break;
                case MITRE:
                    mitre = xcp.map();
                    break;
                case COMPLIANCE:
                    compliance = xcp.map();
                    break;
                case METADATA:
                    metadata = xcp.map();
                    break;
                case DOCUMENT_ID_FIELD:
                    documentId = xcp.textOrNull();
                    break;
                case SPACE_FIELD:
                    space = xcp.textOrNull();
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        Rule rule =
                new Rule(
                        id,
                        version,
                        Objects.requireNonNull(category, "Rule Category is null"),
                        Objects.requireNonNull(logSource, "Rule LogSource is null"),
                        references,
                        tags,
                        level,
                        falsePositives,
                        status,
                        date,
                        queries,
                        queryFields,
                        Objects.requireNonNull(original, "Rule String is null"),
                        aggregationQueries,
                        mitre,
                        compliance,
                        metadata);
        rule.setDocumentId(documentId);
        rule.setSpace(space);
        return rule;
    }

    public static Rule readFrom(StreamInput sin) throws IOException {
        return new Rule(sin);
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    public String getId() {
        return this.id;
    }

    public Long getVersion() {
        return this.version;
    }

    public String getCategory() {
        return this.category;
    }

    public String getTitle() {
        if (this.metadata != null) {
            Object titleObj = this.metadata.get("title");
            if (titleObj instanceof String) {
                return (String) titleObj;
            }
        }
        return null;
    }

    public String getLogSource() {
        return this.logSource;
    }

    public String getDescription() {
        if (this.metadata != null) {
            Object titleObj = this.metadata.get("description");
            if (titleObj instanceof String) {
                return (String) titleObj;
            }
        }
        return null;
    }

    public List<Value> getTags() {
        return this.tags;
    }

    public List<Value> getReferences() {
        return this.references;
    }

    public String getLevel() {
        return this.level;
    }

    public List<Value> getFalsePositives() {
        return this.falsePositives;
    }

    public String getAuthor() {
        if (this.metadata != null) {
            Object titleObj = this.metadata.get("author");
            if (titleObj instanceof String) {
                return (String) titleObj;
            }
        }
        return null;
    }

    public String getStatus() {
        return this.status;
    }

    public Instant getDate() {
        return this.date;
    }

    public String getRule() {
        return this.rule;
    }

    public List<Value> getQueries() {
        return this.queries;
    }

    public List<Value> getQueryFieldNames() {
        return this.queryFieldNames;
    }

    public List<Value> getAggregationQueries() {
        return this.aggregationQueries;
    }

    public boolean isAggregationRule() {
        return this.aggregationQueries != null && !this.aggregationQueries.isEmpty();
    }

    public Map<String, Object> getMitre() {
        return this.mitre;
    }

    public Map<String, Object> getComplianceMap() {
        return this.complianceMap;
    }

    public Map<String, Object> getMetadata() {
        return this.metadata;
    }

    /**
     * Gets the original document ID from the Content Manager plugin.
     *
     * @return the original document UUID, or null if not set
     */
    public String getDocumentId() {
        return this.documentId;
    }

    /**
     * Sets the original document ID from the Content Manager plugin.
     *
     * @param documentId the UUID of the original document in the Content Manager
     */
    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }

    /**
     * Gets the space this rule belongs to.
     *
     * @return the space name (e.g., "draft", "test", "custom"), or null if not set
     */
    public String getSpace() {
        return this.space;
    }

    /**
     * Sets the space this rule belongs to.
     *
     * @param space the space name
     */
    public void setSpace(String space) {
        this.space = space;
    }

    public List<AggregationItem> getAggregationItemsFromRule() throws SigmaConditionError {
        SigmaRule sigmaRule = SigmaRule.fromYaml(this.rule, true);
        // TODO: Check if there are cx errors from the rule created and throw errors
        List<AggregationItem> aggregationItems = new ArrayList<>();
        for (SigmaCondition condition : sigmaRule.getDetection().getParsedCondition()) {
            Pair<ConditionItem, AggregationItem> parsedItems = condition.parsed();
            AggregationItem aggItem = parsedItems.getRight();
            aggItem.setTimeframe(sigmaRule.getDetection().getTimeframe());
            aggregationItems.add(aggItem);
        }
        return aggregationItems;
    }
}
