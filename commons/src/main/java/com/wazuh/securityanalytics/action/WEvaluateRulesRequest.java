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
 * Request to evaluate a list of Sigma rules against a normalized event.
 *
 * @see WEvaluateRulesAction
 */
public class WEvaluateRulesRequest extends ActionRequest {

    /** The normalized event as a JSON string. */
    private final String normalizedEvent;

    /** The list of Sigma rule bodies to evaluate. */
    private final List<String> rulesBodies;

    /**
     * Constructs a new WEvaluateRulesRequest.
     *
     * @param normalizedEvent the normalized event as a JSON string
     * @param rulesBodies the list of Sigma rule bodies to evaluate
     */
    public WEvaluateRulesRequest(String normalizedEvent, List<String> rulesBodies) {
        super();
        this.normalizedEvent = normalizedEvent;
        this.rulesBodies = rulesBodies;
    }

    /**
     * Constructs a WEvaluateRulesRequest by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WEvaluateRulesRequest(StreamInput sin) throws IOException {
        super(sin);
        this.normalizedEvent = sin.readString();
        this.rulesBodies = sin.readStringList();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(normalizedEvent);
        out.writeStringCollection(rulesBodies);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (normalizedEvent == null || normalizedEvent.isEmpty()) {
            validationException =
                    addValidationError("normalizedEvent must not be null or empty", validationException);
        }
        if (rulesBodies == null || rulesBodies.isEmpty()) {
            validationException =
                    addValidationError("rulesBodies must not be null or empty", validationException);
        }
        return validationException;
    }

    /**
     * Gets the normalized event JSON.
     *
     * @return the event JSON string
     */
    public String getEventJson() {
        return normalizedEvent;
    }

    /**
     * Gets the list of Sigma rule bodies.
     *
     * @return the rule bodies
     */
    public List<String> getRulesBodies() {
        return rulesBodies;
    }
}
