/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.model;

import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class    Integration implements Writeable, ToXContentObject {

    public static final List<String> VALID_CATEGORIES = List.of(
            "Access Management",
            "Applications",
            "Cloud Services",
            "Network Activity",
            "Security",
            "System Activity",
            "Other"
    );

    public static final String CUSTOM_LOG_TYPE_ID_FIELD = "custom_logtype_id";

    private static final String NAME_FIELD = "name";

    private static final String DESCRIPTION_FIELD = "description";

    private static final String CATEGORY_FIELD = "category";
    private static final String SOURCE_FIELD = "source";

    private static final String TAGS_FIELD = "tags";

    private String id;

    private Long version;

    private String name;

    private String description;

    private String category;

    private String source;

    private Map<String, Object> tags;

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            Integration.class,
            new ParseField("logType"),
            xcp -> parse(xcp, null, null)
    );

    public Integration(String id,
                       Long version,
                       String name,
                       String description,
                       String category,
                       String source,
                       Map<String, Object> tags) {
        this.id = id != null ? id : "";
        this.version = version != null ? version : 1L;
        this.name = name;
        this.description = description;
        this.category = category != null? category: "Other";
        this.source = source;
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
                (Map<String, Object>) input.get(TAGS_FIELD)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeString(name);
        out.writeString(description);
        out.writeString(category);
        out.writeString(source);
        out.writeMap(tags);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(NAME_FIELD, name)
                .field(DESCRIPTION_FIELD, description)
                .field(CATEGORY_FIELD, category)
                .field(SOURCE_FIELD, source)
                .field(TAGS_FIELD, tags)
                .endObject();
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
                default:
                    xcp.skipChildren();
            }
        }
        return new Integration(id, version, name, description, category, source, tags);
    }

    public static Integration readFrom(StreamInput sin) throws IOException {
        return new Integration(sin);
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    public Long getVersion() {
        return version;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getCategory() {
        return category;
    }

    public String getSource() {
        return source;
    }

    public void setTags(Map<String, Object> tags) {
        this.tags = tags;
    }

    public Map<String, Object> getTags() {
        return tags;
    }
}