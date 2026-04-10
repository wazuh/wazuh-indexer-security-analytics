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

/**
 * Request to bulk-delete all Security Analytics resources belonging to a space. The {@code space}
 * field corresponds to the SAP source name (e.g. "sigma", "custom-xxx").
 */
public class WDeleteSpaceResourcesRequest extends ActionRequest {

    private final String space;
    private final WriteRequest.RefreshPolicy refreshPolicy;

    public WDeleteSpaceResourcesRequest(String space, WriteRequest.RefreshPolicy refreshPolicy) {
        this.space = space;
        this.refreshPolicy = refreshPolicy;
    }

    public WDeleteSpaceResourcesRequest(StreamInput sin) throws IOException {
        this(sin.readString(), WriteRequest.RefreshPolicy.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (this.space == null || this.space.isEmpty()) {
            validationException = addValidationError("space is required", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.space);
        this.refreshPolicy.writeTo(out);
    }

    public String getSpace() {
        return this.space;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return this.refreshPolicy;
    }
}
