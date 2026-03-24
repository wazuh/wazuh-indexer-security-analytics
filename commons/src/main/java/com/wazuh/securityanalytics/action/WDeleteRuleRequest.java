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

public class WDeleteRuleRequest extends ActionRequest {

    private final String ruleId;
    private final WriteRequest.RefreshPolicy refreshPolicy;
    private final Boolean forced;
    private final String documentId;
    private final String space;

    public WDeleteRuleRequest(
            String ruleId, WriteRequest.RefreshPolicy refreshPolicy, Boolean forced) {
        this(ruleId, refreshPolicy, forced, null, null);
    }

    public WDeleteRuleRequest(
            String ruleId,
            WriteRequest.RefreshPolicy refreshPolicy,
            Boolean forced,
            String documentId,
            String space) {
        this.ruleId = ruleId;
        this.refreshPolicy = refreshPolicy;
        this.forced = forced;
        this.documentId = documentId;
        this.space = space;
    }

    public WDeleteRuleRequest(StreamInput sin) throws IOException {
        this(
            sin.readString(),
            WriteRequest.RefreshPolicy.readFrom(sin),
            sin.readBoolean(),
            sin.readOptionalString(),
            sin.readOptionalString()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;

        boolean ruleIdMissing = this.ruleId == null || this.ruleId.isEmpty();
        boolean documentIdMissing = this.documentId == null || this.documentId.isEmpty();
        boolean sourceMissing = this.source == null || this.source.isEmpty();

        // Require either a ruleId, or both documentId and source
        if (ruleIdMissing && (documentIdMissing || sourceMissing)) {
            validationException = addValidationError(
                "ruleId or (documentId and source) is required",
                validationException
            );
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.ruleId);
        this.refreshPolicy.writeTo(out);
        out.writeBoolean(this.forced);
        out.writeOptionalString(this.documentId);
        out.writeOptionalString(this.space);
    }

    public String getRuleId() {
        return this.ruleId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return this.refreshPolicy;
    }

    public Boolean isForced() {
        return this.forced;
    }

    public String getDocumentId() {
        return this.documentId;
    }

    public String getSpace() {
        return this.space;
    }
}
