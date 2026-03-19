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

import com.wazuh.securityanalytics.model.Integration;

/**
 * Response for a Wazuh integration indexing operation.
 *
 * <p>Contains the result of an integration create/update operation, including the integration's ID,
 * version number, REST status, and the complete integration data.
 *
 * <p>This class implements {@link ToXContentObject} to support REST API serialization.
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

    private final Integration integration;

    /**
     * Constructs a new WIndexIntegrationResponse.
     *
     * @param id the ID of the indexed integration
     * @param version the version number of the indexed integration
     * @param status the REST status of the operation
     * @param integration the complete integration data
     */
    public WIndexIntegrationResponse(
            String id, Long version, RestStatus status, Integration integration) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.integration = integration;
    }

    /**
     * Constructs a WIndexIntegrationResponse by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WIndexIntegrationResponse(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readEnum(RestStatus.class),
                Integration.readFrom(sin));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        out.writeLong(this.version);
        out.writeEnum(this.status);
        this.integration.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder
                .startObject()
                .field("_id", this.id)
                .field("_version", this.version)
                .field(CUSTOM_LOG_TYPES_FIELD, this.integration)
                .endObject();
    }

    /**
     * Gets the ID of the indexed integration.
     *
     * @return the integration ID
     */
    public String getId() {
        return this.id;
    }
}
