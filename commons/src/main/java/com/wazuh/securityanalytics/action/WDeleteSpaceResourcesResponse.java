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

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Response for the bulk space-resource deletion action. Reports how many integrations and rules
 * were deleted and whether any errors occurred.
 */
public class WDeleteSpaceResourcesResponse extends ActionResponse implements ToXContentObject {

    private final int deletedIntegrations;
    private final int deletedRules;
    private final boolean hasFailures;
    private final String failureMessage;

    public WDeleteSpaceResourcesResponse(
            int deletedIntegrations, int deletedRules, boolean hasFailures, String failureMessage) {
        this.deletedIntegrations = deletedIntegrations;
        this.deletedRules = deletedRules;
        this.hasFailures = hasFailures;
        this.failureMessage = failureMessage;
    }

    public WDeleteSpaceResourcesResponse(StreamInput sin) throws IOException {
        this(sin.readVInt(), sin.readVInt(), sin.readBoolean(), sin.readOptionalString());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeVInt(this.deletedIntegrations);
        out.writeVInt(this.deletedRules);
        out.writeBoolean(this.hasFailures);
        out.writeOptionalString(this.failureMessage);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params)
            throws IOException {
        return builder
                .startObject()
                .field("deleted_integrations", this.deletedIntegrations)
                .field("deleted_rules", this.deletedRules)
                .field("has_failures", this.hasFailures)
                .field("failure_message", this.failureMessage)
                .endObject();
    }

    public int getDeletedIntegrations() {
        return this.deletedIntegrations;
    }

    public int getDeletedRules() {
        return this.deletedRules;
    }

    public boolean hasFailures() {
        return this.hasFailures;
    }

    public String getFailureMessage() {
        return this.failureMessage;
    }
}
