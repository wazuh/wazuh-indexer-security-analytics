/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

public class WIndexDetectorResponse extends ActionResponse {
    private String id;
    private Long version;

    public WIndexDetectorResponse(String id, Long version) {
        super();
        this.id = id;
        this.version = version;
    }

    public WIndexDetectorResponse(StreamInput sin) throws IOException {
        this(sin.readString(),
             sin.readLong());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
    }


    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }
}