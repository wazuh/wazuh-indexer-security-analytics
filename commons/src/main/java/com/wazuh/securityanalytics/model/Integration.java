/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.model;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class Integration implements Writeable, ToXContentObject {

    public static final List<String> WAZUH_CATEGORIES = List.of(
        "Access Management",
        "Applications",
        "Cloud Services",
        "Network Activity",
        "Security",
        "System Activity",
        "Other"
    );

    private static final String NAME_FIELD = "name";

    private static final String DESCRIPTION_FIELD = "description";

    private static final String CATEGORY_FIELD = "category";
    private static final String SOURCE_FIELD = "source";

    private static final String TAGS_FIELD = "tags";

    private static final String RULES_FIELD = "rules";

    private String id;

    private Long version;

    private final String name;

    private final String description;

    private final String category;

    private final String source;

    private final List<String> ruleIds;

    private Map<String, Object> tags;

    public Integration(String id,
                       Long version,
                       String name,
                       String description,
                       String category,
                       String source,
                       List<String> ruleIds,
                       Map<String, Object> tags) {
        this.id = id != null ? id : "";
        this.version = version != null ? version : 1L;
        this.name = name;
        this.description = description;
        this.category = category;
        this.source = source;
        this.ruleIds = ruleIds;
        this.tags = tags;
    }

    public Integration(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readStringList(),
                sin.readMap()
        );
    }

    @SuppressWarnings("unchecked")
    public Integration(Map<String, Object> input) {
        this(
                null,
                null,
                input.get(NAME_FIELD).toString(),
                input.get(DESCRIPTION_FIELD).toString(),
                input.containsKey(CATEGORY_FIELD)? input.get(CATEGORY_FIELD).toString(): null,
                input.get(SOURCE_FIELD).toString(),
                input.get(RULES_FIELD) != null ?
                        (List<String>) input.get(RULES_FIELD) : null,
                (Map<String, Object>) input.get(TAGS_FIELD)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        out.writeLong(this.version);
        out.writeString(this.name);
        out.writeString(this.description);
        out.writeString(this.category);
        out.writeString(this.source);
        out.writeStringCollection(this.ruleIds);
        out.writeMap(this.tags);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(NAME_FIELD, this.name)
                .field(DESCRIPTION_FIELD, this.description)
                .field(CATEGORY_FIELD, this.category)
                .field(SOURCE_FIELD, this.source)
                .field(TAGS_FIELD, this.tags)
                .array(RULES_FIELD, this.ruleIds)
                .endObject();
    }

    public XContentBuilder toXContent() throws IOException {
        return this.toXContent(XContentFactory.jsonBuilder(), null);
    }

    public static Integration parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = "";
        }
        if (version == null) {
            version = 1L;
        }

        String name = null;
        String description = null;
        String category = null;
        String source = null;
        Map<String, Object> tags = null;
        List<String> rules = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case NAME_FIELD:
                    name = xcp.text();
                    break;
                case DESCRIPTION_FIELD:
                    description = xcp.text();
                    break;
                case CATEGORY_FIELD:
                    category = xcp.textOrNull();
                    break;
                case SOURCE_FIELD:
                    source = xcp.text();
                    break;
                case TAGS_FIELD:
                    tags = xcp.map();
                    break;
                case RULES_FIELD:
//                    rules = xcp.list();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new Integration(id, version, name, description, category, source, rules, tags);
    }

    public static Integration readFrom(StreamInput sin) throws IOException {
        return new Integration(sin);
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return this.id;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    public Long getVersion() {
        return this.version;
    }

    public String getName() {
        return this.name;
    }

    public String getDescription() {
        return this.description;
    }

    public String getCategory() {
        return this.category;
    }

    public String getSource() {
        return this.source;
    }

    public void setTags(Map<String, Object> tags) {
        this.tags = tags;
    }

    public Map<String, Object> getTags() {
        return this.tags;
    }

    public List<String> getRuleIds() {
        return this.ruleIds;
    }
}