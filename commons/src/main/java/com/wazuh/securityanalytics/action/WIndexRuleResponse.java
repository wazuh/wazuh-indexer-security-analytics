/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;

public class WIndexRuleResponse extends ActionResponse implements ToXContentObject {

    /**
     * the id of the created/updated rule
     */
    private String id;

    /**
     * the version of the created/updated rule
     */
    private Long version;

    /**
     * REST method for the request PUT/POST
     */
    private RestStatus status;


    public WIndexRuleResponse(String id, Long version, RestStatus status) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
    }

    public WIndexRuleResponse(StreamInput sin) throws IOException {
        this(sin.readString(),
             sin.readLong(),
             sin.readEnum(RestStatus.class));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .field("_id", id)
            .field("_version", version);
        return builder;
    }

    public String getId() {
        return id;
    }
}
