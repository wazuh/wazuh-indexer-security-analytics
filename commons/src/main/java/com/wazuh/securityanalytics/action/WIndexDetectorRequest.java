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

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.List;

/**
 * Request for indexing a Wazuh detector.
 *
 * <p>This request contains all the information needed to create or update a detector, including the
 * detector ID, log type name, category, associated rules, and refresh policy.
 *
 * @see WIndexDetectorAction
 * @see WIndexDetectorResponse
 */
public class WIndexDetectorRequest extends ActionRequest {
    private final String detectorId;
    private final String logTypeName;
    private final String category;
    private final List<String> rules;
    private final WriteRequest.RefreshPolicy refreshPolicy;

    /**
     * Constructs a new WIndexDetectorRequest.
     *
     * @param detectorId the unique identifier for the detector
     * @param logTypeName the name of the log type this detector monitors
     * @param category the category of logs this detector analyzes
     * @param rules list of rule IDs to associate with this detector
     * @param refreshPolicy the refresh policy for the index operation
     */
    public WIndexDetectorRequest(
            String detectorId,
            String logTypeName,
            String category,
            List<String> rules,
            WriteRequest.RefreshPolicy refreshPolicy) {
        super();
        this.detectorId = detectorId;
        this.logTypeName = logTypeName;
        this.category = category;
        this.rules = rules;
        this.refreshPolicy = refreshPolicy;
    }

    /**
     * Constructs a WIndexDetectorRequest by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WIndexDetectorRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readStringList(),
                WriteRequest.RefreshPolicy.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.detectorId);
        out.writeString(this.logTypeName);
        out.writeString(this.category);
        out.writeStringCollection(this.rules);
        this.refreshPolicy.writeTo(out);
    }

    public String getDetectorId() {
        return this.detectorId;
    }

    public String getLogTypeName() {
        return this.logTypeName;
    }

    public String getCategory() {
        return this.category;
    }

    public List<String> getRules() {
        return this.rules;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return this.refreshPolicy;
    }
}
