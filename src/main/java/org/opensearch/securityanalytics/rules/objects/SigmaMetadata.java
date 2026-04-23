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
package org.opensearch.securityanalytics.rules.objects;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Wazuh-specific metadata block for Sigma rules. Fields here take precedence over top-level
 * equivalents for title and description.
 */
public class SigmaMetadata {

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

    /**
     * Constructs a new SigmaMetadata instance.
     *
     * @param title the title of the rule
     * @param author the author of the rule
     * @param date the creation date of the rule
     * @param modified the last modification date of the rule
     * @param description a description of the rule
     * @param references a list of references or URLs related to the rule
     * @param documentation link to additional documentation
     * @param module the module associated with the rule
     * @param versions supported versions of the rule format or software
     * @param compatibility software or system compatibility information
     * @param supports list of supported features or platforms
     */
    public SigmaMetadata(
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

    /**
     * Creates a {@link SigmaMetadata} instance from a Map representation. This is typically used when
     * parsing the metadata block from a YAML or JSON source.
     *
     * @param map a map containing metadata keys and values
     * @return a new {@link SigmaMetadata} instance, or null if the input map is null
     */
    @SuppressWarnings("unchecked")
    public static SigmaMetadata fromDict(Map<String, Object> map) {
        if (map == null) {
            return null;
        }
        return new SigmaMetadata(
                map.get("title") != null ? map.get("title").toString() : null,
                map.get("author") != null ? map.get("author").toString() : null,
                map.get("date") != null ? map.get("date").toString() : null,
                map.get("modified") != null ? map.get("modified").toString() : null,
                map.get("description") != null ? map.get("description").toString() : null,
                map.get("references") instanceof List ? (List<String>) map.get("references") : null,
                map.get("documentation") != null ? map.get("documentation").toString() : null,
                map.get("module") != null ? map.get("module").toString() : null,
                map.get("versions") instanceof List ? (List<String>) map.get("versions") : null,
                map.get("compatibility") instanceof List ? (List<String>) map.get("compatibility") : null,
                map.get("supports") instanceof List ? (List<String>) map.get("supports") : null);
    }

    /**
     * Converts the metadata object into a Map for indexing or serialization purposes. Only non-null
     * and non-empty fields are included in the resulting map.
     *
     * @return a map containing the metadata fields
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        if (this.title != null) {
            map.put("title", this.title);
        }
        if (this.author != null) {
            map.put("author", this.author);
        }
        if (this.date != null) {
            map.put("date", this.date);
        }
        if (this.modified != null) {
            map.put("modified", this.modified);
        }
        if (this.description != null) {
            map.put("description", this.description);
        }
        if (this.references != null && !this.references.isEmpty()) {
            map.put("references", this.references);
        }
        if (this.documentation != null) {
            map.put("documentation", this.documentation);
        }
        if (this.module != null) {
            map.put("module", this.module);
        }
        if (this.versions != null && !this.versions.isEmpty()) {
            map.put("versions", this.versions);
        }
        if (this.compatibility != null && !this.compatibility.isEmpty()) {
            map.put("compatibility", this.compatibility);
        }
        if (this.supports != null && !this.supports.isEmpty()) {
            map.put("supports", this.supports);
        }
        return map;
    }

    /**
     * @return the title of the rule
     */
    public String getTitle() {
        return this.title;
    }

    /**
     * @return the author of the rule
     */
    public String getAuthor() {
        return this.author;
    }

    /**
     * @return the creation date of the rule
     */
    public String getDate() {
        return this.date;
    }

    /**
     * @return the last modification date of the rule
     */
    public String getModified() {
        return this.modified;
    }

    /**
     * @return the description of the rule
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * @return the list of references for the rule
     */
    public List<String> getReferences() {
        return this.references;
    }

    /**
     * @return the documentation link
     */
    public String getDocumentation() {
        return this.documentation;
    }

    /**
     * @return the module name
     */
    public String getModule() {
        return this.module;
    }

    /**
     * @return the list of supported versions
     */
    public List<String> getVersions() {
        return this.versions;
    }

    /**
     * @return the list of compatibility targets
     */
    public List<String> getCompatibility() {
        return this.compatibility;
    }

    /**
     * @return the list of supported features or platforms
     */
    public List<String> getSupports() {
        return this.supports;
    }
}
