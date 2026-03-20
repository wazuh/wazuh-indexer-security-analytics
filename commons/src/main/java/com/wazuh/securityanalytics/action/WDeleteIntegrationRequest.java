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

import java.io.IOException;

import static org.opensearch.action.ValidateActions.addValidationError;

public class WDeleteIntegrationRequest extends ActionRequest {

    private final String logTypeId;
    private final WriteRequest.RefreshPolicy refreshPolicy;
    private final String documentId;
    private final String source;

    public WDeleteIntegrationRequest(String logTypeId, WriteRequest.RefreshPolicy refreshPolicy) {
        this(logTypeId, refreshPolicy, null, null);
    }

    public WDeleteIntegrationRequest(String logTypeId, WriteRequest.RefreshPolicy refreshPolicy, String documentId, String source) {
        this.logTypeId = logTypeId;
        this.refreshPolicy = refreshPolicy;
        this.documentId = documentId;
        this.source = source;
    }

    public WDeleteIntegrationRequest(StreamInput sin) throws IOException {
        this(sin.readString(), WriteRequest.RefreshPolicy.readFrom(sin), sin.readOptionalString(), sin.readOptionalString());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if ((this.logTypeId == null || this.logTypeId.isEmpty()) && (this.documentId == null || this.documentId.isEmpty())) {
            validationException = addValidationError("logTypeId or documentId is required", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.logTypeId);
        this.refreshPolicy.writeTo(out);
        out.writeOptionalString(this.documentId);
        out.writeOptionalString(this.source);
    }

    public String getLogTypeId() {
        return this.logTypeId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return this.refreshPolicy;
    }

    public String getDocumentId() {
        return this.documentId;
    }

    public String getSource() {
        return this.source;
    }
}
