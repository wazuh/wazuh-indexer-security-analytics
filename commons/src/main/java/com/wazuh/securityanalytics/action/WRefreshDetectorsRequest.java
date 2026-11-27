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
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.List;

import static org.opensearch.action.ValidateActions.addValidationError;

/**
 * Request to rebuild the detectors that reference any of the given rules.
 *
 * <p>A caller that updates several rules with {@code skipDetectorRebuild} set sends this request
 * once afterwards, so each affected detector is rebuilt once instead of once per rule.
 *
 * @see WRefreshDetectorsAction
 */
public class WRefreshDetectorsRequest extends ActionRequest {

    /** Ids of the rules that changed, as the detectors reference them. */
    private final List<String> ruleIds;

    /**
     * Constructs a new WRefreshDetectorsRequest.
     *
     * @param ruleIds ids of the rules that changed
     */
    public WRefreshDetectorsRequest(List<String> ruleIds) {
        super();
        this.ruleIds = ruleIds;
    }

    /**
     * Constructs a WRefreshDetectorsRequest by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WRefreshDetectorsRequest(StreamInput sin) throws IOException {
        this(sin.readStringList());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (this.ruleIds == null || this.ruleIds.isEmpty()) {
            validationException = addValidationError("rule ids are missing", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringCollection(this.ruleIds);
    }

    public List<String> getRuleIds() {
        return this.ruleIds;
    }
}
