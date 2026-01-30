package com.wazuh.securityanalytics.action;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import static org.opensearch.action.ValidateActions.addValidationError;

public class WDeleteCustomRuleRequest extends ActionRequest {

    private final String ruleId;
    private final WriteRequest.RefreshPolicy refreshPolicy;
    private final Boolean forced;

    public WDeleteCustomRuleRequest(String ruleId, WriteRequest.RefreshPolicy refreshPolicy, Boolean forced) {
        this.ruleId = ruleId;
        this.refreshPolicy = refreshPolicy;
        this.forced = forced;
    }

    public WDeleteCustomRuleRequest(StreamInput sin) throws IOException {
        this(sin.readString(), WriteRequest.RefreshPolicy.readFrom(sin), sin.readBoolean());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (this.ruleId == null || this.ruleId.isEmpty()) {
            validationException = addValidationError("ruleId is missing", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.ruleId);
        this.refreshPolicy.writeTo(out);
        out.writeBoolean(this.forced);
    }

    public String getRuleId() {
        return this.ruleId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return this.refreshPolicy;
    }

    public Boolean isForced() {
        return this.forced;
    }
}
