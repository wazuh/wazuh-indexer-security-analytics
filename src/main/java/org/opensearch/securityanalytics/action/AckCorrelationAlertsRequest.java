/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ValidateActions;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class AckCorrelationAlertsRequest extends ActionRequest {
    private final List<String> correlationAlertIds;

    public AckCorrelationAlertsRequest(List<String> correlationAlertIds) {
        this.correlationAlertIds = correlationAlertIds;
    }

    public AckCorrelationAlertsRequest(StreamInput in) throws IOException {
        correlationAlertIds = Collections.unmodifiableList(in.readStringList());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if(correlationAlertIds == null || correlationAlertIds.isEmpty()) {
            validationException = ValidateActions.addValidationError("alert ids list cannot be empty", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringCollection(this.correlationAlertIds);
    }

    public List<String> getCorrelationAlertIds() {
        return correlationAlertIds;
    }
}
