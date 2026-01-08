package com.wazuh.securityanalytics.action;

import java.io.IOException;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class WDeleteIntegrationResponse extends ActionResponse implements ToXContentObject {
    private final String id;
    private final Long version;
    private final RestStatus status;

    public WDeleteIntegrationResponse(String id, Long version, RestStatus status) {
        this.id = id;
        this.version = version;
        this.status = status;
    }

    public WDeleteIntegrationResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readLong(), (RestStatus)sin.readEnum(RestStatus.class));
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        out.writeLong(this.version);
        out.writeEnum(this.status);
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        return builder.startObject().field("_id", this.id).field("_version", this.version).field("result", this.status).endObject();
    }

    public String getId() {
        return this.id;
    }
}
