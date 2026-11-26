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
import java.util.List;

/**
 * Response of a rule validation: the queries the rule compiles to.
 *
 * @see WValidateRuleAction
 */
public class WValidateRuleResponse extends ActionResponse implements ToXContentObject {

    /** The compiled queries of the rule. */
    private final List<String> queries;

    /**
     * Constructs a new WValidateRuleResponse.
     *
     * @param queries the compiled queries of the rule
     */
    public WValidateRuleResponse(List<String> queries) {
        super();
        this.queries = queries;
    }

    /**
     * Constructs a WValidateRuleResponse by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WValidateRuleResponse(StreamInput sin) throws IOException {
        this(sin.readStringList());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringCollection(this.queries);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject().field("queries", this.queries).endObject();
    }

    /**
     * Gets the compiled queries of the rule.
     *
     * @return the compiled queries
     */
    public List<String> getQueries() {
        return this.queries;
    }
}
