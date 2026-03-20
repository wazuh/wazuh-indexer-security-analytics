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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Response for a Wazuh rule indexing operation.
 *
 * <p>Contains the result of a rule create/update operation, including the rule's ID, version
 * number, and REST status.
 *
 * <p>This class implements {@link ToXContentObject} to support REST API serialization.
 *
 * @see WIndexRuleAction
 * @see WIndexRuleRequest
 */
public class WIndexRuleResponse extends ActionResponse implements ToXContentObject {

    /** The ID of the created/updated rule. */
    private String id;

    /** The version of the created/updated rule. */
    private Long version;

    /** The REST status of the operation. */
    private RestStatus status;

    /**
     * Constructs a new WIndexRuleResponse.
     *
     * @param id the ID of the indexed rule
     * @param version the version number of the indexed rule
     * @param status the REST status of the operation
     */
    public WIndexRuleResponse(String id, Long version, RestStatus status) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
    }

    /**
     * Constructs a WIndexRuleResponse by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WIndexRuleResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readLong(), sin.readEnum(RestStatus.class));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        out.writeLong(this.version);
        out.writeEnum(this.status);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field("_id", this.id).field("_version", this.version);
        return builder;
    }

    /**
     * Gets the ID of the indexed rule.
     *
     * @return the rule ID
     */
    public String getId() {
        return this.id;
    }
}
