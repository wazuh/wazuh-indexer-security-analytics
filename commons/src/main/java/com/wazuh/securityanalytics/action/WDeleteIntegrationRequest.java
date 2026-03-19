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

    public WDeleteIntegrationRequest(String logTypeId, WriteRequest.RefreshPolicy refreshPolicy) {
        this.logTypeId = logTypeId;
        this.refreshPolicy = refreshPolicy;
    }

    public WDeleteIntegrationRequest(StreamInput sin) throws IOException {
        this(sin.readString(), WriteRequest.RefreshPolicy.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (logTypeId == null || logTypeId.isEmpty()) {
            validationException = addValidationError("logTypeId is missing", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(logTypeId);
        refreshPolicy.writeTo(out);
    }

    public String getLogTypeId() {
        return logTypeId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }
}
