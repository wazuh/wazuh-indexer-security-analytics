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

public class IndexDetectorRequest extends ActionRequest {

    private String detectorId;

    private WriteRequest.RefreshPolicy refreshPolicy;

    private RestRequest.Method method;

    private Detector detector;

    public IndexDetectorRequest(
            String detectorId,
            WriteRequest.RefreshPolicy refreshPolicy,
            RestRequest.Method method,
            Detector detector) {
        super();
        this.detectorId = detectorId;
        this.refreshPolicy = refreshPolicy;
        this.method = method;
        this.detector = detector;
    }

    public IndexDetectorRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                WriteRequest.RefreshPolicy.readFrom(sin),
                sin.readEnum(RestRequest.Method.class),
                Detector.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        refreshPolicy.writeTo(out);
        out.writeEnum(method);
        detector.writeTo(out);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    public Detector getDetector() {
        return detector;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }

    public void setDetector(Detector detector) {
        this.detector = detector;
    }
}
