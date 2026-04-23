/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.securityanalytics.rules.exceptions.SigmaDateError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaDetectionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaIdentifierError;
import org.opensearch.securityanalytics.rules.exceptions.CompositeSigmaErrors;
import org.opensearch.securityanalytics.rules.exceptions.SigmaLevelError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaLogsourceError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTitleError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaStatusError;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.representer.Representer;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

public class SigmaRule {

    private String title;

    private SigmaLogSource logSource;

    private SigmaDetections detection;

    private UUID id;

    private SigmaStatus status;

    private String description;

    private List<String> references;

    private List<SigmaRuleTag> tags;

    private String author;

    private Date date;

    private List<String> fields;

    private List<String> falsePositives;

    private SigmaLevel level;

    private CompositeSigmaErrors errors;

    private SigmaMetadata metadata;

    private SigmaMitre mitre;

    private SigmaCompliance compliance;

    public SigmaRule(String title, SigmaLogSource logSource, SigmaDetections detection, UUID id, SigmaStatus status,
                     String description, List<String> references, List<SigmaRuleTag> tags, String author, Date date,
                     List<String> fields, List<String> falsePositives, SigmaLevel level, CompositeSigmaErrors errors) {
        this(title, logSource, detection, id, status, description, references, tags, author, date,
                fields, falsePositives, level, errors, null, null, null);
    }

    public SigmaRule(String title, SigmaLogSource logSource, SigmaDetections detection, UUID id, SigmaStatus status,
                     String description, List<String> references, List<SigmaRuleTag> tags, String author, Date date,
                     List<String> fields, List<String> falsePositives, SigmaLevel level, CompositeSigmaErrors errors,
                     SigmaMetadata metadata, SigmaMitre mitre, SigmaCompliance compliance) {
        this.title = title;
        this.logSource = logSource;
        this.detection = detection;
        this.id = id;
        this.status = status;
        this.description = description;
        this.references = references;
        this.tags = tags;
        this.author = author;
        this.date = date;
        this.fields = fields;
        this.falsePositives = falsePositives;
        this.level = level;

        this.errors = errors;

        this.metadata = metadata;
        this.mitre = mitre;
        this.compliance = compliance;

        if (this.references == null) {
            this.references = new ArrayList<>();
        }
        if (this.tags == null) {
            this.tags = new ArrayList<>();
        }
        if (this.fields == null) {
            this.fields = new ArrayList<>();
        }
        if (this.falsePositives == null) {
            this.falsePositives = new ArrayList<>();
        }
    }

    @SuppressWarnings("unchecked")
    protected static SigmaRule fromDict(Map<String, Object> rule, boolean collectErrors) {
        CompositeSigmaErrors errors = new CompositeSigmaErrors();

        // 1. Parse metadata FIRST to apply the new normalized schema
        SigmaMetadata metadata = null;
        if (rule.containsKey("metadata")) {
            try {
                metadata = SigmaMetadata.fromDict((Map<String, Object>) rule.get("metadata"));
            } catch (Exception ex) {
                errors.addError(new SigmaError("Invalid metadata block: " + ex.getMessage()));
            }
        }

        UUID ruleId;
        if (rule.containsKey("id")) {
            try {
                ruleId = UUID.fromString(rule.get("id").toString());
            } catch (IllegalArgumentException ex) {
                errors.addError(new SigmaIdentifierError("Sigma rule identifier must be an UUID"));
                ruleId = null;
            }
        } else {
            errors.addError(new SigmaIdentifierError("Sigma rule identifier cannot be null"));
            ruleId = null;
        }

        // 2. Extract Title (Metadata takes precedence)
        String title = null;
        if (metadata != null && metadata.getTitle() != null) {
            title = metadata.getTitle();
        } else if (rule.containsKey("title")) {
            title = rule.get("title").toString();
        }

        if (title == null) {
            title = "";
        } else if (!title.matches("^.{1,256}$")) {
            errors.addError(new SigmaTitleError("Sigma rule title can be max 256 characters"));
        }

        SigmaLevel level = null;
        if (rule.containsKey("level")) {
            try {
                level = SigmaLevel.valueOf(rule.get("level").toString().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ex) {
                errors.addError(new SigmaLevelError("Value of level not correct"));
            }
        } else {
            errors.addError(new SigmaLevelError("Sigma rule level cannot be null"));
        }

        SigmaStatus status = null;
        if (rule.containsKey("status")) {
            try {
                status = SigmaStatus.valueOf(rule.get("status").toString().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ex) {
                errors.addError(new SigmaStatusError("Value of status not correct"));
            }
        } else {
            errors.addError(new SigmaStatusError("Sigma rule status cannot be null"));
        }

        // 3. Extract Date (Metadata takes precedence)
        Date ruleDate = null;
        Object dateObj = (metadata != null && metadata.getDate() != null) ? metadata.getDate() : rule.get("date");
        if (dateObj != null) {
            try {
                String dateStr = dateObj.toString();
                if (dateStr.contains("/")) {
                    SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd", Locale.getDefault());
                    ruleDate = formatter.parse(dateStr);
                } else if (dateStr.contains("-")) {
                    SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd", Locale.getDefault());
                    ruleDate = formatter.parse(dateStr);
                }
            } catch (Exception ex) {
                errors.addError(new SigmaDateError("Rule date " + dateObj + " is invalid, must be yyyy/mm/dd or yyyy-mm-dd"));
            }
        }

        SigmaLogSource logSource = null;
        if (rule.containsKey("logsource")) {
            try {
                logSource = SigmaLogSource.fromDict((Map<String, Object>) rule.get("logsource"));
            } catch (SigmaLogsourceError ex) {
                errors.addError(new SigmaLogsourceError("Sigma rule must have a log source"));
            }
        } else {
            errors.addError(new SigmaLogsourceError("Sigma rule must have a log source"));
        }

        SigmaDetections detections = null;
        if (rule.containsKey("detection")) {
            try {
                detections = SigmaDetections.fromDict((Map<String, Object>) rule.get("detection"));
            } catch (SigmaError ex) {
                errors.addError(new SigmaDetectionError("Sigma rule must have a detection definitions"));
            }
        } else {
            errors.addError(new SigmaDetectionError("Sigma rule must have a detection definitions"));
        }

        List<String> ruleTagsStr = (List<String>) rule.get("tags");
        List<SigmaRuleTag> ruleTags = new ArrayList<>();
        if (ruleTagsStr != null) {
            for (String ruleTag : ruleTagsStr) {
                ruleTags.add(SigmaRuleTag.fromStr(ruleTag));
            }
        }

        SigmaMitre mitre = null;
        if (rule.containsKey("mitre")) {
            try {
                mitre = SigmaMitre.fromDict((Map<String, Object>) rule.get("mitre"));
            } catch (SigmaError ex) {
                errors.addError(ex);
            }
        }

        SigmaCompliance compliance = null;
        if (rule.containsKey("compliance")) {
            Object compObj = rule.get("compliance");
            if (compObj instanceof Map) {
                try {
                    compliance = SigmaCompliance.fromMap((Map<String, Object>) compObj);
                } catch (SigmaError ex) {
                    errors.addError(ex);
                }
            } else {
                errors.addError(new SigmaError("Compliance block must be an object containing framework lists"));
            }
        }

        if (rule.containsKey("detection")) {
            try {
                WCSFieldValidator.validateDetectionFields((Map<String, Object>) rule.get("detection"));
            } catch (SigmaError ex) {
                errors.addError(ex);
            }
        }

        if (!collectErrors && !errors.getErrors().isEmpty()) {
            throw errors;
        }

        // 4. Extract remaining shared fields (Metadata takes precedence)
        String description = (metadata != null && metadata.getDescription() != null) ? metadata.getDescription() : (rule.get("description") != null ? rule.get("description").toString() : null);
        String author = (metadata != null && metadata.getAuthor() != null) ? metadata.getAuthor() : (rule.get("author") != null ? rule.get("author").toString() : null);
        List<String> references = (metadata != null && metadata.getReferences() != null && !metadata.getReferences().isEmpty()) ? metadata.getReferences() : (rule.get("references") != null ? (List<String>) rule.get("references") : null);

        return new SigmaRule(title, logSource, detections, ruleId, status,
                description, references, ruleTags, author, ruleDate,
                rule.get("fields") != null? (List<String>) rule.get("fields"): null,
                rule.get("falsepositives") != null? (List<String>) rule.get("falsepositives"): null, level, errors,
                metadata, mitre, compliance);
    }

    public static SigmaRule fromYaml(String rule, boolean collectErrors) {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setNestingDepthLimit(10);

        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()), new Representer(new DumperOptions()), new DumperOptions(), loaderOptions);
        Map<String, Object> ruleMap = yaml.load(rule);
        return fromDict(ruleMap, collectErrors);
    }

    public String getTitle() {
        return title;
    }

    public SigmaLogSource getLogSource() {
        return logSource;
    }

    public SigmaDetections getDetection() {
        return detection;
    }

    public UUID getId() {
        return id;
    }

    public SigmaStatus getStatus() {
        return status;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getReferences() {
        return references;
    }

    public List<SigmaRuleTag> getTags() {
        return tags;
    }

    public String getAuthor() {
        return author;
    }

    public Date getDate() {
        return date;
    }

    public List<String> getFields() {
        return fields;
    }

    public List<String> getFalsePositives() {
        return falsePositives;
    }

    public SigmaLevel getLevel() {
        return level;
    }

    public CompositeSigmaErrors getErrors() {
        return errors;
    }

    public SigmaMetadata getMetadata() {
        return metadata;
    }

    public SigmaMitre getMitre() {
        return mitre;
    }

    public SigmaCompliance getCompliance() {
        return compliance;
    }
}
