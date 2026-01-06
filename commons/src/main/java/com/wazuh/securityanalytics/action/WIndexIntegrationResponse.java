/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package com.wazuh.securityanalytics.action;

import java.io.IOException;

import com.wazuh.securityanalytics.model.Integration;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

/**
 * Response for a Wazuh integration indexing operation.
 *
 * Contains the result of an integration create/update operation, including the
 * integration's ID, version number, REST status, and the complete integration data.
 *
 * This class implements {@link ToXContentObject} to support REST API serialization.
 *
 * @see WIndexIntegrationAction
 * @see WIndexIntegrationRequest
 * @see Integration
 */
public class WIndexIntegrationResponse extends ActionResponse implements ToXContentObject {

    /** Field name for the log type in XContent output. */
    public static final String CUSTOM_LOG_TYPES_FIELD = "logType";

    private final String id;

    private final Long version;

    private final RestStatus status;

    private final Integration customLogType;

    /**
     * Constructs a new WIndexIntegrationResponse.
     *
     * @param id            the ID of the indexed integration
     * @param version       the version number of the indexed integration
     * @param status        the REST status of the operation
     * @param customLogType the complete integration data
     */
    public WIndexIntegrationResponse(String id, Long version, RestStatus status, Integration customLogType) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.customLogType = customLogType;
    }

    /**
     * Constructs a WIndexIntegrationResponse by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WIndexIntegrationResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readLong(), sin.readEnum(RestStatus.class), Integration.readFrom(sin));
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
