/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import com.wazuh.securityanalytics.model.DetectorRule;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.List;

public class WIndexDetectorRequest extends ActionRequest {
    private String logTypeName;
    private List<DetectorRule> rules;
    private WriteRequest.RefreshPolicy refreshPolicy;

    public WIndexDetectorRequest(
            String logTypeName,
            List<DetectorRule> rules,
            WriteRequest.RefreshPolicy refreshPolicy) {
        super();
        this.logTypeName = logTypeName;
        this.rules = rules;
        this.refreshPolicy = refreshPolicy;
    }

    public WIndexDetectorRequest(StreamInput sin) throws IOException {
        this(sin.readString(),
             sin.readList(DetectorRule::new),
             WriteRequest.RefreshPolicy.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.logTypeName);
        out.writeList(this.rules);
        this.refreshPolicy.writeTo(out);
    }

    public String getLogTypeName() {
        return logTypeName;
    }

    public List<DetectorRule> getRules() {
        return rules;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }
}