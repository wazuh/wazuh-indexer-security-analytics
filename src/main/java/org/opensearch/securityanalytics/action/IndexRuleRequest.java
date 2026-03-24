/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.util.Locale;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;

import java.io.IOException;


import static org.opensearch.action.ValidateActions.addValidationError;

public class IndexRuleRequest extends ActionRequest {

    /**
     * the ruleId to update
     */
    private final String ruleId;

    /**
     * refreshPolicy for create/update
     */
    private final WriteRequest.RefreshPolicy refreshPolicy;

    /**
     * the log type of the rule which has 1-1 mapping to log type. We have 8 pre-defined log types today.
     */
    private final String logType;

    /**
     * REST method for the request PUT/POST
     */
    private final RestRequest.Method method;

    /**
     * the actual Sigma Rule yaml
     */
    private final String rule;

    /**
     * this boolean field forces updating of rule from any running detectors & updates detector metadata.
     * setting this to false, will result in throwing an error if rule is actively used by other detectors.
     */
    private final Boolean forced;

    private final String documentId;

    private final String space;

    public IndexRuleRequest(
            String ruleId,
            WriteRequest.RefreshPolicy refreshPolicy,
            String logType,
            RestRequest.Method method,
            String rule,
            Boolean forced
    ) {
        this(ruleId, refreshPolicy, logType, method, rule, forced, null, null);
    }

    public IndexRuleRequest(
            String ruleId,
            WriteRequest.RefreshPolicy refreshPolicy,
            String logType,
            RestRequest.Method method,
            String rule,
            Boolean forced,
            String documentId,
            String space
    ) {
        super();
        this.ruleId = ruleId;
        this.refreshPolicy = refreshPolicy;
        this.logType = logType.toLowerCase(Locale.ROOT);
        this.method = method;
        this.rule = rule;
        this.forced = forced;
        this.documentId = documentId;
        this.space = space;
    }

    public IndexRuleRequest(StreamInput sin) throws IOException {
        this(sin.readString(),
             WriteRequest.RefreshPolicy.readFrom(sin),
             sin.readString(),
             sin.readEnum(RestRequest.Method.class),
             sin.readString(),
             sin.readBoolean(),
             sin.readOptionalString(),
             sin.readOptionalString());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;

        if (this.logType == null || this.logType.isEmpty()) {
            validationException = addValidationError("rule categoty is missing", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.ruleId);
        this.refreshPolicy.writeTo(out);
        out.writeString(this.logType);
        out.writeEnum(this.method);
        out.writeString(this.rule);
        out.writeBoolean(this.forced);
        out.writeOptionalString(this.documentId);
        out.writeOptionalString(this.space);
    }

    public String getRuleId() {
        return this.ruleId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return this.refreshPolicy;
    }

    public String getLogType() {
        return this.logType;
    }

    public RestRequest.Method getMethod() {
        return this.method;
    }

    public String getRule() {
        return this.rule;
    }

    public Boolean isForced() {
        return this.forced;
    }

    public String getDocumentId() {
        return this.documentId;
    }

    public String getSpace() {
        return this.space;
    }
}