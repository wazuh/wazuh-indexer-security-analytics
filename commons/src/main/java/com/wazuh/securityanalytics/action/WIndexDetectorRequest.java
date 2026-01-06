/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import java.io.IOException;
import java.util.List;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

public class WIndexDetectorRequest extends ActionRequest {
    private final String detectorId;
    private final String logTypeName;
    private final String category;
    private final List<String> rules;
    private final WriteRequest.RefreshPolicy refreshPolicy;

    public WIndexDetectorRequest(
        String detectorId,
        String logTypeName,
        String category,
        List<String> rules,
        WriteRequest.RefreshPolicy refreshPolicy
    ) {
        super();
        this.detectorId = detectorId;
        this.logTypeName = logTypeName;
        this.category = category;
        this.rules = rules;
        this.refreshPolicy = refreshPolicy;
    }

    public WIndexDetectorRequest(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readString(), sin.readString(), sin.readStringList(), WriteRequest.RefreshPolicy.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.detectorId);
        out.writeString(this.logTypeName);
        out.writeString(this.category);
        out.writeStringCollection(this.rules);
        this.refreshPolicy.writeTo(out);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public String getLogTypeName() {
        return this.logTypeName;
    }

    public String getCategory() {
        return this.category;
    }

    public List<String> getRules() {
        return this.rules;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return this.refreshPolicy;
    }
}
