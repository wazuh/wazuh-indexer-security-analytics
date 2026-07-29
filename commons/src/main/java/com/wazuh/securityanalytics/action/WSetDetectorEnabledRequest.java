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

/** Request to toggle the {@code enabled} state of an existing detector, identified by its id. */
public class WSetDetectorEnabledRequest extends ActionRequest {

    private final String detectorId;
    private final boolean enabled;
    private final WriteRequest.RefreshPolicy refreshPolicy;

    public WSetDetectorEnabledRequest(
            String detectorId, boolean enabled, WriteRequest.RefreshPolicy refreshPolicy) {
        this.detectorId = detectorId;
        this.enabled = enabled;
        this.refreshPolicy = refreshPolicy;
    }

    public WSetDetectorEnabledRequest(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readBoolean(), WriteRequest.RefreshPolicy.readFrom(sin));
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
        out.writeBoolean(enabled);
        refreshPolicy.writeTo(out);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }
}
