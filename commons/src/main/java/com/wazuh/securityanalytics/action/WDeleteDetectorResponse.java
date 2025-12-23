//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.wazuh.securityanalytics.action;

import java.io.IOException;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;

public class WDeleteDetectorResponse extends ActionResponse {
    private final String id;
    private final Long version;
    private final RestStatus status;

    public WDeleteDetectorResponse(String id, Long version, RestStatus status) {
        this.id = id;
        this.version = version;
        this.status = status;
    }

    public WDeleteDetectorResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readLong(), (RestStatus)sin.readEnum(RestStatus.class));
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        out.writeLong(this.version);
        out.writeEnum(this.status);
    }

    public String getId() {
        return this.id;
    }
}
