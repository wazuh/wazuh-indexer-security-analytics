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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.opensearch.securityanalytics.action.IndexCustomLogTypeResponse.CUSTOM_LOG_TYPES_FIELD;
import static org.opensearch.securityanalytics.model.Detector.NO_ID;
import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class CustomLogType implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(CustomLogType.class);

    public static final List<String> VALID_LOG_CATEGORIES =
            List.of(
                    "Access Management",
                    "Applications",
                    "Cloud Services",
                    "Network Activity",
                    "Security",
                    "System Activity",
                    "Other",
                    "Unclassified");

    public static final String CUSTOM_LOG_TYPE_ID_FIELD = "custom_logtype_id";

    private static final String NAME_FIELD = "name";

    private static final String DESCRIPTION_FIELD = "description";

    private static final String CATEGORY_FIELD = "category";
    private static final String SOURCE_FIELD = "source";

    private static final String TAGS_FIELD = "tags";

    private static final String DOCUMENT_ID_FIELD = "document.id";

    private String id;

    private Long version;

    private final String name;

    private final String description;

    private final String category;

    private final String source;

    private Map<String, Object> tags;

    private String documentId;

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY =
            new NamedXContentRegistry.Entry(
                    CustomLogType.class,
                    new ParseField(CUSTOM_LOG_TYPES_FIELD),
                    xcp -> CustomLogType.parse(xcp, null, null));

    public CustomLogType(
            String id,
            Long version,
            String name,
            String description,
            String category,
            String source,
            Map<String, Object> tags) {
        this(id, version, name, description, category, source, tags, null);
    }

    public CustomLogType(
            String id,
            Long version,
            String name,
            String description,
            String category,
            String source,
            Map<String, Object> tags,
            String documentId) {
        this.id = id != null ? id : NO_ID;
        this.version = version != null ? version : NO_VERSION;
        this.name = name;
        this.description = description;
        this.category = category != null ? category : "Other";
        this.source = source;
        this.tags = tags;
        this.documentId = documentId;
    }

    public CustomLogType(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readMap(),
                sin.readOptionalString());
    }

    @SuppressWarnings("unchecked")
    public CustomLogType(Map<String, Object> input) {
        this(
                null,
                null,
                input.get(NAME_FIELD).toString(),
                input.get(DESCRIPTION_FIELD).toString(),
                input.containsKey(CATEGORY_FIELD) ? input.get(CATEGORY_FIELD).toString() : null,
                input.get(SOURCE_FIELD).toString(),
                (Map<String, Object>) input.get(TAGS_FIELD),
                input.containsKey(DOCUMENT_ID_FIELD) ? input.get(DOCUMENT_ID_FIELD).toString() : null);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        out.writeLong(this.version);
        out.writeString(this.name);
        out.writeString(this.description);
        out.writeString(this.category);
        out.writeString(this.source);
        out.writeMap(this.tags);
        out.writeOptionalString(this.documentId);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder
                .startObject()
                .field(NAME_FIELD, this.name)
                .field(DESCRIPTION_FIELD, this.description)
                .field(CATEGORY_FIELD, this.category)
                .field(SOURCE_FIELD, this.source)
                .field(TAGS_FIELD, this.tags);
        if (this.documentId != null) {
            builder.field(DOCUMENT_ID_FIELD, this.documentId);
        }
        return builder.endObject();
    }

    public static CustomLogType parse(XContentParser xcp, String id, Long version)
            throws IOException {
        if (id == null) {
            id = NO_ID;
        }
        if (version == null) {
            version = NO_VERSION;
        }

        String name = null;
        String description = null;
        String category = null;
        String source = null;
        Map<String, Object> tags = null;
        String documentId = null;

        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
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
                case DOCUMENT_ID_FIELD:
                    documentId = xcp.textOrNull();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new CustomLogType(id, version, name, description, category, source, tags, documentId);
    }

    public static CustomLogType readFrom(StreamInput sin) throws IOException {
        return new CustomLogType(sin);
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

    public String getDocumentId() {
        return this.documentId;
    }

    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }
}
