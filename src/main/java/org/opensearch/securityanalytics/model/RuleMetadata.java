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

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Typed view of the rule metadata block. Mirrors {@link
 * org.opensearch.securityanalytics.rules.objects.SigmaMetadata} so the model layer can carry the
 * metadata as structured data rather than a raw map. Wire and JSON formats are kept identical to
 * the previous {@code Map<String, Object>} representation by routing serialization through {@link
 * #toMap()} / {@link #fromMap(Map)}.
 */
public class RuleMetadata implements Writeable, ToXContentObject {

    public static final String TITLE = "title";
    public static final String AUTHOR = "author";
    public static final String DATE = "date";
    public static final String MODIFIED = "modified";
    public static final String DESCRIPTION = "description";
    public static final String REFERENCES = "references";
    public static final String DOCUMENTATION = "documentation";
    public static final String MODULE = "module";
    public static final String VERSIONS = "versions";
    public static final String COMPATIBILITY = "compatibility";
    public static final String SUPPORTS = "supports";

    private final String title;
    private final String author;
    private final String date;
    private final String modified;
    private final String description;
    private final List<String> references;
    private final String documentation;
    private final String module;
    private final List<String> versions;
    private final List<String> compatibility;
    private final List<String> supports;

    public RuleMetadata(
            String title,
            String author,
            String date,
            String modified,
            String description,
            List<String> references,
            String documentation,
            String module,
            List<String> versions,
            List<String> compatibility,
            List<String> supports) {
        this.title = title;
        this.author = author;
        this.date = date;
        this.modified = modified;
        this.description = description;
        this.references = references != null ? references : Collections.emptyList();
        this.documentation = documentation;
        this.module = module;
        this.versions = versions != null ? versions : Collections.emptyList();
        this.compatibility = compatibility != null ? compatibility : Collections.emptyList();
        this.supports = supports != null ? supports : Collections.emptyList();
    }

    public static RuleMetadata empty() {
        return new RuleMetadata(null, null, null, null, null, null, null, null, null, null, null);
    }

    @SuppressWarnings("unchecked")
    public RuleMetadata(StreamInput sin) throws IOException {
        this((Map<String, Object>) sin.readGenericValue());
    }

    private RuleMetadata(Map<String, Object> map) {
        this(
                map != null && map.get(TITLE) != null ? map.get(TITLE).toString() : null,
                map != null && map.get(AUTHOR) != null ? map.get(AUTHOR).toString() : null,
                map != null && map.get(DATE) != null ? map.get(DATE).toString() : null,
                map != null && map.get(MODIFIED) != null ? map.get(MODIFIED).toString() : null,
                map != null && map.get(DESCRIPTION) != null ? map.get(DESCRIPTION).toString() : null,
                map != null && map.get(REFERENCES) instanceof List
                        ? castStringList(map.get(REFERENCES))
                        : null,
                map != null && map.get(DOCUMENTATION) != null
                        ? map.get(DOCUMENTATION).toString()
                        : null,
                map != null && map.get(MODULE) != null ? map.get(MODULE).toString() : null,
                map != null && map.get(VERSIONS) instanceof List
                        ? castStringList(map.get(VERSIONS))
                        : null,
                map != null && map.get(COMPATIBILITY) instanceof List
                        ? castStringList(map.get(COMPATIBILITY))
                        : null,
                map != null && map.get(SUPPORTS) instanceof List
                        ? castStringList(map.get(SUPPORTS))
                        : null);
    }

    @SuppressWarnings("unchecked")
    private static List<String> castStringList(Object value) {
        return (List<String>) value;
    }

    public static RuleMetadata fromMap(Map<String, Object> map) {
        return new RuleMetadata(map);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        if (this.title != null) {
            map.put(TITLE, this.title);
        }
        if (this.author != null) {
            map.put(AUTHOR, this.author);
        }
        if (this.date != null) {
            map.put(DATE, this.date);
        }
        if (this.modified != null) {
            map.put(MODIFIED, this.modified);
        }
        if (this.description != null) {
            map.put(DESCRIPTION, this.description);
        }
        if (this.references != null && !this.references.isEmpty()) {
            map.put(REFERENCES, this.references);
        }
        if (this.documentation != null) {
            map.put(DOCUMENTATION, this.documentation);
        }
        if (this.module != null) {
            map.put(MODULE, this.module);
        }
        if (this.versions != null && !this.versions.isEmpty()) {
            map.put(VERSIONS, this.versions);
        }
        if (this.compatibility != null && !this.compatibility.isEmpty()) {
            map.put(COMPATIBILITY, this.compatibility);
        }
        if (this.supports != null && !this.supports.isEmpty()) {
            map.put(SUPPORTS, this.supports);
        }
        return map;
    }

    public boolean isEmpty() {
        return toMap().isEmpty();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeGenericValue(this.toMap());
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.map(this.toMap());
    }

    public static RuleMetadata parse(XContentParser xcp) throws IOException {
        return fromMap(xcp.map());
    }

    public static RuleMetadata readFrom(StreamInput sin) throws IOException {
        return new RuleMetadata(sin);
    }

    public String getTitle() {
        return this.title;
    }

    public String getAuthor() {
        return this.author;
    }

    public String getDate() {
        return this.date;
    }

    public String getModified() {
        return this.modified;
    }

    public String getDescription() {
        return this.description;
    }

    public List<String> getReferences() {
        return this.references;
    }

    public String getDocumentation() {
        return this.documentation;
    }

    public String getModule() {
        return this.module;
    }

    public List<String> getVersions() {
        return this.versions;
    }

    public List<String> getCompatibility() {
        return this.compatibility;
    }

    public List<String> getSupports() {
        return this.supports;
    }
}
