package com.wazuh.securityanalytics.action;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import static org.opensearch.action.ValidateActions.addValidationError;

public class WDeleteDetectorRequest extends ActionRequest {

    private final String detectorId;
    private final WriteRequest.RefreshPolicy refreshPolicy;

    public WDeleteDetectorRequest(String detectorId, WriteRequest.RefreshPolicy refreshPolicy) {
        this.detectorId = detectorId;
        this.refreshPolicy = refreshPolicy;
    }

    public WDeleteDetectorRequest(StreamInput sin) throws IOException {
        this(sin.readString(), WriteRequest.RefreshPolicy.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (detectorId == null || detectorId.isEmpty()) {
            validationException = addValidationError("detectorId is missing", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        refreshPolicy.writeTo(out);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }
}
