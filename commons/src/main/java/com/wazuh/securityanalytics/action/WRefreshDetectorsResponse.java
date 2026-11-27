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
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Response of a detector refresh: how many detectors were rebuilt.
 *
 * @see WRefreshDetectorsAction
 */
public class WRefreshDetectorsResponse extends ActionResponse implements ToXContentObject {

    /** Number of detectors rebuilt. */
    private final int detectors;

    /**
     * Constructs a new WRefreshDetectorsResponse.
     *
     * @param detectors number of detectors rebuilt
     */
    public WRefreshDetectorsResponse(int detectors) {
        super();
        this.detectors = detectors;
    }

    /**
     * Constructs a WRefreshDetectorsResponse by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WRefreshDetectorsResponse(StreamInput sin) throws IOException {
        this(sin.readVInt());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeVInt(this.detectors);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject().field("detectors", this.detectors).endObject();
    }

    /**
     * Gets the number of detectors rebuilt.
     *
     * @return the number of detectors rebuilt
     */
    public int getDetectors() {
        return this.detectors;
    }
}
