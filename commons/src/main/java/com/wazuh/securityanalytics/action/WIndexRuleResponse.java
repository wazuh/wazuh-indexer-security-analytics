/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

/**
 * Response for a Wazuh rule indexing operation.
 *
 * Contains the result of a rule create/update operation, including the
 * rule's ID, version number, and REST status.
 *
 * This class implements {@link ToXContentObject} to support REST API serialization.
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
     * @param id      the ID of the indexed rule
     * @param version the version number of the indexed rule
     * @param status  the REST status of the operation
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
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field("_id", id).field("_version", version);
        return builder;
    }

    public String getId() {
        return id;
    }
}
