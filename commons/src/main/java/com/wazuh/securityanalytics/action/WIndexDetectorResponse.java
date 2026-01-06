/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

/**
 * Response for a Wazuh detector indexing operation.
 *
 * Contains the result of a detector create/update operation, including the
 * detector's ID and version number.
 *
 * @see WIndexDetectorAction
 * @see WIndexDetectorRequest
 */
public class WIndexDetectorResponse extends ActionResponse {
    private final String id;
    private final Long version;

    /**
     * Constructs a new WIndexDetectorResponse.
     *
     * @param id      the ID of the indexed detector
     * @param version the version number of the indexed detector
     */
    public WIndexDetectorResponse(String id, Long version) {
        super();
        this.id = id;
        this.version = version;
    }

    /**
     * Constructs a WIndexDetectorResponse by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WIndexDetectorResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readLong());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        out.writeLong(this.version);
    }

    public String getId() {
        return this.id;
    }

    public Long getVersion() {
        return this.version;
    }
}
