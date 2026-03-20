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
package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;

public class WIndexCustomRuleRequest extends ActionRequest {

    private final String ruleId;
    private final WriteRequest.RefreshPolicy refreshPolicy;
    private final String logType;
    private final RestRequest.Method method;
    private final String rule;
    private final Boolean forced;
    private final String documentId;
    private final String source;

    public WIndexCustomRuleRequest(
            String ruleId,
            WriteRequest.RefreshPolicy refreshPolicy,
            String logType,
            RestRequest.Method method,
            String rule,
            Boolean forced) {
        this(ruleId, refreshPolicy, logType, method, rule, forced, null, null);
    }

    public WIndexCustomRuleRequest(
            String ruleId,
            WriteRequest.RefreshPolicy refreshPolicy,
            String logType,
            RestRequest.Method method,
            String rule,
            Boolean forced,
            String documentId,
            String source) {
        super();
        this.ruleId = ruleId;
        this.refreshPolicy = refreshPolicy;
        this.logType = logType.toLowerCase(Locale.ROOT);
        this.method = method;
        this.rule = rule;
        this.forced = forced;
        this.documentId = documentId;
        this.source = source;
    }

    public WIndexCustomRuleRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(),
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
        out.writeOptionalString(this.documentId);
        out.writeOptionalString(this.source);
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

    public String getSource() {
        return this.source;
    }
}
