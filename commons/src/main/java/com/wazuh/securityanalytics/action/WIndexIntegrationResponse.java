/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package com.wazuh.securityanalytics.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import com.wazuh.securityanalytics.model.Integration;

import java.io.IOException;

public class WIndexIntegrationResponse extends ActionResponse implements ToXContentObject {

    public static final String CUSTOM_LOG_TYPES_FIELD = "logType";

    private final String id;

    private final Long version;

    private final RestStatus status;

    private final Integration customLogType;

    public WIndexIntegrationResponse(
            String id,
            Long version,
            RestStatus status,
            Integration customLogType
    ) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.customLogType = customLogType;
    }

    public WIndexIntegrationResponse(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readEnum(RestStatus.class),
                Integration.readFrom(sin)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        out.writeLong(this.version);
        out.writeEnum(this.status);
        this.customLogType.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field("_id", this.id)
                .field("_version", this.version)
                .field(CUSTOM_LOG_TYPES_FIELD, this.customLogType)
                .endObject();
    }

    public String getId() {
        return this.id;
    }
}
