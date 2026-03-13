/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Wazuh-specific metadata block for Sigma rules.
 * Fields here take precedence over top-level equivalents for title and description.
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

    public SigmaMetadata(String title, String author, String date, String modified, String description,
                         List<String> references, String documentation, String module,
                         List<String> versions, List<String> compatibility, List<String> supports) {
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
                map.get("supports") instanceof List ? (List<String>) map.get("supports") : null
        );
    }

    /**
     * Converts metadata to a Map for indexing.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        if (title != null){
            map.put("title", title);
        }
        if (author != null){
            map.put("author", author);
        }
        if (date != null){
            map.put("date", date);
        }
        if (modified != null){
            map.put("modified", modified);
        }
        if (description != null){
            map.put("description", description);
        }
        if (references != null && !references.isEmpty()){
            map.put("references", references);
        }
        if (documentation != null){
            map.put("documentation", documentation);
        }
        if (module != null){
            map.put("module", module);
        }
        if (versions != null && !versions.isEmpty()){
            map.put("versions", versions);
        }
        if (compatibility != null && !compatibility.isEmpty()){
            map.put("compatibility", compatibility);
        }
        if (supports != null && !supports.isEmpty()){
            map.put("supports", supports);
        }
        return map;
    }

    public String getTitle() {
        return title;
    }

    public String getAuthor() {
        return author;
    }

    public String getDate() {
        return date;
    }

    public String getModified() {
        return modified;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getReferences() {
        return references;
    }

    public String getDocumentation() {
        return documentation;
    }

    public String getModule() {
        return module;
    }

    public List<String> getVersions() {
        return versions;
    }

    public List<String> getCompatibility() {
        return compatibility;
    }

    public List<String> getSupports() {
        return supports;
    }
}
