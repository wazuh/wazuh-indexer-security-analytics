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
    private final String space;

    public WDeleteIntegrationRequest(String logTypeId, WriteRequest.RefreshPolicy refreshPolicy) {
        this(logTypeId, refreshPolicy, null, null);
    }

    public WDeleteIntegrationRequest(
            String logTypeId, WriteRequest.RefreshPolicy refreshPolicy, String documentId, String space) {
        this.logTypeId = logTypeId;
        this.refreshPolicy = refreshPolicy;
        this.documentId = documentId;
        this.space = space;
    }

    public WDeleteIntegrationRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                WriteRequest.RefreshPolicy.readFrom(sin),
                sin.readOptionalString(),
                sin.readOptionalString());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;

        boolean hasLogTypeId = this.logTypeId != null && this.logTypeId.isEmpty() == false;
        boolean hasDocumentId = this.documentId != null && this.documentId.isEmpty() == false;
        boolean hasSpace = this.space != null && this.space.isEmpty() == false;

        // Valid combinations:
        //   - logTypeId is present (documentId/space ignored), OR
        //   - both documentId and space are present.
        if (hasLogTypeId) {
            return null;
        }

        if (hasDocumentId && hasSpace) {
            return null;
        }

        if (!hasDocumentId && !hasSpace) {
            validationException =
                    addValidationError(
                            "logTypeId or (documentId and space) is required", validationException);
        } else if (hasDocumentId && !hasSpace) {
            validationException =
                    addValidationError("space is required when documentId is provided", validationException);
        } else if (!hasDocumentId && hasSpace) {
            validationException =
                    addValidationError("documentId is required when space is provided", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.logTypeId);
        this.refreshPolicy.writeTo(out);
        out.writeOptionalString(this.documentId);
        out.writeOptionalString(this.space);
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

    public String getSpace() {
        return this.space;
    }
}
