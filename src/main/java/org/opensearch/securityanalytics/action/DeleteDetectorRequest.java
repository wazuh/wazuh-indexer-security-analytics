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
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

public class DeleteDetectorRequest extends ActionRequest {

    private String detectorId;
    private WriteRequest.RefreshPolicy refreshPolicy;

    /**
     * When true the request originates from an internal plugin (e.g. Content Manager) and should
     * bypass the standard-detector deletion restriction.
     */
    private final boolean internalCaller;

    public DeleteDetectorRequest(String detectorId, WriteRequest.RefreshPolicy refreshPolicy) {
        this(detectorId, refreshPolicy, false);
    }

    public DeleteDetectorRequest(
            String detectorId, WriteRequest.RefreshPolicy refreshPolicy, boolean internalCaller) {
        super();
        this.detectorId = detectorId;
        this.refreshPolicy = refreshPolicy;
        this.internalCaller = internalCaller;
    }

    public DeleteDetectorRequest(StreamInput sin) throws IOException {
        this(sin.readString(), WriteRequest.RefreshPolicy.readFrom(sin), sin.readBoolean());
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        refreshPolicy.writeTo(out);
        out.writeBoolean(internalCaller);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }

    public boolean isInternalCaller() {
        return internalCaller;
    }
}
