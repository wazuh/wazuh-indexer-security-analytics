/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import java.io.IOException;
import java.util.Locale;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;

import static org.opensearch.action.ValidateActions.addValidationError;

public class WIndexCustomRuleRequest extends ActionRequest {

    private final String ruleId;
    private final WriteRequest.RefreshPolicy refreshPolicy;
    private final String logType;
    private final RestRequest.Method method;
    private final String rule;
    private final Boolean forced;

    public WIndexCustomRuleRequest(
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

    public WIndexCustomRuleRequest(StreamInput sin) throws IOException {
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
        if (this.logType == null || this.logType.isEmpty()) {
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
