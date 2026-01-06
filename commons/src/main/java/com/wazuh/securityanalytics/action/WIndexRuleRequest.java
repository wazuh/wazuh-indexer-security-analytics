/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import java.io.IOException;
import java.util.Locale;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import static org.opensearch.action.ValidateActions.addValidationError;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;

/**
 * Request for indexing a Wazuh rule.
 *
 * This request contains all the information needed to create or update a Sigma rule,
 * including the rule ID, log type, HTTP method, rule YAML content, and force flag.
 *
 * The log type is automatically converted to lowercase during construction.
 *
 * @see WIndexRuleAction
 * @see WIndexRuleResponse
 */
public class WIndexRuleRequest extends ActionRequest {

    /** The rule ID to update. */
    private final String ruleId;

    /** Refresh policy for create/update operations. */
    private final WriteRequest.RefreshPolicy refreshPolicy;

    /** The log type of the rule which maps 1-1 to a log type category. */
    private final String logType;

    /** REST method for the request (PUT for update, POST for create). */
    private final RestRequest.Method method;

    /** The actual Sigma Rule YAML content. */
    private final String rule;

    /**
     * Forces updating the rule even if it is used by running detectors.
     * If false, an error is thrown when the rule is actively used by detectors.
     */
    private final Boolean forced;

    /**
     * Constructs a new WIndexRuleRequest.
     *
     * @param ruleId        the unique identifier for the rule
     * @param refreshPolicy the refresh policy for the index operation
     * @param logType       the log type category for this rule (will be lowercased)
     * @param method        the HTTP method (PUT for update, POST for create)
     * @param rule          the Sigma rule YAML content
     * @param forced        if true, updates the rule even if used by active detectors
     */
    public WIndexRuleRequest(
        String ruleId,
        WriteRequest.RefreshPolicy refreshPolicy,
        String logType,
        RestRequest.Method method,
        String rule,
        Boolean forced
    ) {
        super();
        this.ruleId = ruleId;
        this.refreshPolicy = refreshPolicy;
        this.logType = logType.toLowerCase(Locale.ROOT);
        this.method = method;
        this.rule = rule;
        this.forced = forced;
    }

    /**
     * Constructs a WIndexRuleRequest by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WIndexRuleRequest(StreamInput sin) throws IOException {
        this(
            sin.readString(),
            WriteRequest.RefreshPolicy.readFrom(sin),
            sin.readString(),
            sin.readEnum(RestRequest.Method.class),
            sin.readString(),
            sin.readBoolean()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;

        if (this.logType == null || this.logType.length() == 0) {
            validationException = addValidationError("rule category is missing", validationException);
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
}
