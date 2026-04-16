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
package org.opensearch.securityanalytics.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class DetectorRule implements Writeable, ToXContentObject {

    private String id;

    private static final List<String> INVALID_CHARACTERS = List.of(" ", "[", "]", "{", "}", "(", ")");

    protected static final String RULE_ID_FIELD = "id";

    public DetectorRule(String id) {
        if (id == null || id.isEmpty()) {
            throw new IllegalArgumentException("Custom Rule id is invalid");
        }
        this.id = id;
    }

    public DetectorRule(StreamInput sin) throws IOException {
        this(sin.readString());
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(RULE_ID_FIELD, id);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field(RULE_ID_FIELD, id).endObject();
        return builder;
    }

    public static DetectorRule parse(XContentParser xcp) throws IOException {
        String id = null;

        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case RULE_ID_FIELD:
                    id = xcp.text();
                    break;
            }
        }
        return new DetectorRule(id);
    }

    public static DetectorRule readFrom(StreamInput sin) throws IOException {
        return new DetectorRule(sin);
    }

    public String getId() {
        return id;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        DetectorRule that = (DetectorRule) object;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
