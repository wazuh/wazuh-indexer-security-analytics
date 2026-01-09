/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.model;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

/**
 * Represents a Wazuh integration configuration.
 *
 * An integration defines a log type with associated metadata including name, description,
 * category, source, tags, and associated rule IDs. Integrations are used to configure
 * how different log sources are processed and analyzed within Security Analytics.
 *
 * This class implements {@link Writeable} for cluster serialization and {@link ToXContentObject}
 * for REST API responses.
 *
 * @see #WAZUH_CATEGORIES for the list of valid categories
 */
public class Integration implements Writeable, ToXContentObject {

    /**
     * List of valid Wazuh integration categories.
     * Categories are used to classify integrations by their log type domain.
     */
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

    /**
     * Constructs a new Integration with all fields.
     *
     * @param id          the unique identifier for this integration
     * @param version     the version number of this integration
     * @param name        the display name of the integration
     * @param description a description of what this integration does
     * @param category    the category this integration belongs to (must be in WAZUH_CATEGORIES)
     * @param source      the source identifier for this integration
     * @param ruleIds     list of rule IDs associated with this integration
     * @param tags        additional metadata tags for this integration
     */
    public Integration(
        String id,
        Long version,
        String name,
        String description,
        String category,
        String source,
        List<String> ruleIds,
        Map<String, Object> tags
    ) {
        this.id = id != null ? id : "";
        this.version = version != null ? version : 1L;
        this.name = name;
        this.description = description;
        this.category = category;
        this.source = source;
        this.ruleIds = ruleIds;
        this.tags = tags;
    }

    /**
     * Constructs an Integration by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
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

    /**
     * Constructs an Integration from a map of field values.
     *
     * @param input the map containing integration field values
     */
    @SuppressWarnings("unchecked")
    public Integration(Map<String, Object> input) {
        this(
            null,
            null,
            input.get(NAME_FIELD).toString(),
            input.get(DESCRIPTION_FIELD).toString(),
            input.containsKey(CATEGORY_FIELD) ? input.get(CATEGORY_FIELD).toString() : null,
            input.get(SOURCE_FIELD).toString(),
            input.get(RULES_FIELD) != null ? (List<String>) input.get(RULES_FIELD) : null,
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

    /**
     * Convenience method to convert this Integration to XContent using a default JSON builder.
     * This method creates a new JSON builder internally and delegates to the main
     * {@link #toXContent(XContentBuilder, Params)} method.
     *
     * @return An XContentBuilder containing the JSON representation of this integration.
     * @throws IOException If an error occurs during serialization.
     */
    public XContentBuilder toXContent() throws IOException {
        return this.toXContent(XContentFactory.jsonBuilder(), null);
    }

    /**
     * Parses an Integration from XContent.
     *
     * @param xcp     the XContent parser to read from
     * @param id      the integration ID (defaults to empty string if null)
     * @param version the version number (defaults to 1L if null)
     * @return the parsed Integration instance
     * @throws IOException if an I/O error occurs during parsing
     */
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
                case NAME_FIELD -> name = xcp.text();
                case DESCRIPTION_FIELD -> description = xcp.text();
                case CATEGORY_FIELD -> category = xcp.textOrNull();
                case SOURCE_FIELD -> source = xcp.text();
                case TAGS_FIELD -> tags = xcp.map();
                case RULES_FIELD -> {
                }
                default -> xcp.skipChildren();
            }
        }
        return new Integration(id, version, name, description, category, source, rules, tags);
    }

    /**
     * Reads an Integration from the given StreamInput.
     *
     * @param sin the StreamInput to read from
     * @return the deserialized Integration instance
     * @throws IOException if an I/O error occurs during reading
     */
    public static Integration readFrom(StreamInput sin) throws IOException {
        return new Integration(sin);
    }

    /**
     * Sets the ID of the integration.
     *
     * @param id the integration ID
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Gets the ID of the integration.
     *
     * @return the integration ID
     */
    public String getId() {
        return this.id;
    }

    /**
     * Sets the version number of the integration.
     *
     * @param version the version number
     */
    public void setVersion(Long version) {
        this.version = version;
    }

    /**
     * Gets the version number of the integration.
     *
     * @return the version number
     */
    public Long getVersion() {
        return this.version;
    }

    /**
     * Gets the name of the integration.
     *
     * @return the integration name
     */
    public String getName() {
        return this.name;
    }

    /**
     * Gets the description of the integration.
     *
     * @return the integration description
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * Gets the category of the integration.
     *
     * @return the integration category
     */
    public String getCategory() {
        return this.category;
    }

    /**
     * Gets the source of the integration.
     *
     * @return the integration source
     */
    public String getSource() {
        return this.source;
    }

    /**
     * Sets the tags associated with this integration.
     *
     * @param tags a map of tag key-value pairs
     */
    public void setTags(Map<String, Object> tags) {
        this.tags = tags;
    }

    /**
     * Gets the tags associated with this integration.
     *
     * @return a map of tag key-value pairs
     */
    public Map<String, Object> getTags() {
        return this.tags;
    }

    /**
     * Gets the list of rule IDs associated with this integration.
     *
     * @return a list of rule IDs
     */
    public List<String> getRuleIds() {
        return this.ruleIds;
    }
}
