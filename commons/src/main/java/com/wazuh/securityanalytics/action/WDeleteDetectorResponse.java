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

import java.io.IOException;

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
        this(sin.readString(), sin.readLong(), (RestStatus) sin.readEnum(RestStatus.class));
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
