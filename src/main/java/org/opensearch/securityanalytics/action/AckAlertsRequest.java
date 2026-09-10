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
import org.opensearch.action.ValidateActions;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class AckAlertsRequest extends ActionRequest {

    private final String detectorId;

    private final List<String> alertIds;

    public AckAlertsRequest(String detectorId, List<String> alertIds) {
        this.detectorId = detectorId;
        this.alertIds = alertIds;
    }

    public AckAlertsRequest(StreamInput in) throws IOException {
        detectorId = in.readString();
        alertIds = Collections.unmodifiableList(in.readStringList());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (detectorId == null) {
            validationException =
                    ValidateActions.addValidationError("detector id is mandatory", validationException);
        } else if (alertIds == null || alertIds.isEmpty()) {
            validationException =
                    ValidateActions.addValidationError("alert ids list cannot be empty", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.detectorId);
        out.writeStringCollection(this.alertIds);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public List<String> getAlertIds() {
        return alertIds;
    }
}
