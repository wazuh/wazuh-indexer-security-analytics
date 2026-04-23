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

import java.io.IOException;

/**
 * Response for a Wazuh detector indexing operation.
 *
 * <p>Contains the result of a detector create/update operation, including the detector's ID and
 * version number.
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
     * @param id the ID of the indexed detector
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

    /**
     * Gets the ID of the indexed detector.
     *
     * @return the detector ID
     */
    public String getId() {
        return this.id;
    }

    /**
     * Gets the version number of the indexed detector.
     *
     * @return the detector version
     */
    public Long getVersion() {
        return this.version;
    }
}
