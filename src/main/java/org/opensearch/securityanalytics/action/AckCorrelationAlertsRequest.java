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
        if (correlationAlertIds == null || correlationAlertIds.isEmpty()) {
            validationException =
                    ValidateActions.addValidationError("alert ids list cannot be empty", validationException);
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
