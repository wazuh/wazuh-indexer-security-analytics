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
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.model.Detector;

import java.io.IOException;

/**
 * Transport request to create or update a detector. The detector arrives either already parsed, from
 * internal callers that build it themselves, or as the raw request body from the REST layer, for
 * {@code TransportIndexDetectorAction} to parse once privileges have been evaluated.
 */
public class IndexDetectorRequest extends ActionRequest {

    private final String detectorId;

    private final WriteRequest.RefreshPolicy refreshPolicy;

    private final RestRequest.Method method;

    private Detector detector;

    /** Raw request body and its media type, both null when the detector was supplied parsed. */
    private final byte[] body;

    private final String mediaType;

    /**
     * When true the request originates from an internal plugin (e.g. Content Manager) and should
     * bypass the max-detectors limit and preserve the detector source field.
     */
    private final boolean internalCaller;

    public IndexDetectorRequest(
            String detectorId,
            WriteRequest.RefreshPolicy refreshPolicy,
            RestRequest.Method method,
            Detector detector) {
        this(detectorId, refreshPolicy, method, detector, false);
    }

    public IndexDetectorRequest(
            String detectorId,
            WriteRequest.RefreshPolicy refreshPolicy,
            RestRequest.Method method,
            Detector detector,
            boolean internalCaller) {
        super();
        this.detectorId = detectorId;
        this.refreshPolicy = refreshPolicy;
        this.method = method;
        this.detector = detector;
        this.internalCaller = internalCaller;
        this.body = null;
        this.mediaType = null;
    }

    /** Builds a request whose detector the transport action still has to parse from the raw body. */
    public IndexDetectorRequest(
            String detectorId,
            WriteRequest.RefreshPolicy refreshPolicy,
            RestRequest.Method method,
            byte[] body,
            String mediaType) {
        super();
        this.detectorId = detectorId;
        this.refreshPolicy = refreshPolicy;
        this.method = method;
        this.detector = null;
        this.internalCaller = false;
        this.body = body;
        this.mediaType = mediaType;
    }

    public IndexDetectorRequest(StreamInput sin) throws IOException {
        super();
        this.detectorId = sin.readString();
        this.refreshPolicy = WriteRequest.RefreshPolicy.readFrom(sin);
        this.method = sin.readEnum(RestRequest.Method.class);
        this.detector = sin.readBoolean() ? Detector.readFrom(sin) : null;
        this.internalCaller = sin.readBoolean();
        this.body = sin.readBoolean() ? sin.readByteArray() : null;
        this.mediaType = sin.readOptionalString();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.detectorId);
        this.refreshPolicy.writeTo(out);
        out.writeEnum(this.method);
        out.writeBoolean(this.detector != null);
        if (this.detector != null) {
            this.detector.writeTo(out);
        }
        out.writeBoolean(this.internalCaller);
        out.writeBoolean(this.body != null);
        if (this.body != null) {
            out.writeByteArray(this.body);
        }
        out.writeOptionalString(this.mediaType);
    }

    public String getDetectorId() {
        return this.detectorId;
    }

    public RestRequest.Method getMethod() {
        return this.method;
    }

    /** @return the detector, or null while the raw body has not been parsed yet */
    public Detector getDetector() {
        return this.detector;
    }

    public byte[] getBody() {
        return this.body;
    }

    public String getMediaType() {
        return this.mediaType;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return this.refreshPolicy;
    }

    public void setDetector(Detector detector) {
        this.detector = detector;
    }

    public boolean isInternalCaller() {
        return this.internalCaller;
    }
}
