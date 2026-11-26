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
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;

/**
 * Request to validate a Sigma rule without storing it.
 *
 * <p>The rule is compiled in the configuration it would be stored with: a Standard rule as {@link
 * WIndexRuleRequest} compiles it, any other rule as {@link WIndexCustomRuleRequest} does.
 *
 * @see WValidateRuleAction
 */
public class WValidateRuleRequest extends ActionRequest {

    /** The rule's log type (its integration category). */
    private final String logType;

    /** The rule body, YAML or JSON. */
    private final String rule;

    /** Whether the rule is a custom rule, compiled with the log type's field mappings. */
    private final boolean custom;

    /**
     * Constructs a new WValidateRuleRequest.
     *
     * @param logType the rule's log type
     * @param rule the rule body
     * @param custom true to compile as a custom rule, false as a Standard rule
     */
    public WValidateRuleRequest(String logType, String rule, boolean custom) {
        super();
        this.logType = logType == null ? null : logType.toLowerCase(Locale.ROOT);
        this.rule = rule;
        this.custom = custom;
    }

    /**
     * Constructs a WValidateRuleRequest by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WValidateRuleRequest(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readString(), sin.readBoolean());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (this.logType == null || this.logType.isEmpty()) {
            validationException = addValidationError("rule category is missing", validationException);
        }
        if (this.rule == null || this.rule.isEmpty()) {
            validationException = addValidationError("rule body is missing", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.logType);
        out.writeString(this.rule);
        out.writeBoolean(this.custom);
    }

    public String getLogType() {
        return this.logType;
    }

    public String getRule() {
        return this.rule;
    }

    public boolean isCustom() {
        return this.custom;
    }
}
