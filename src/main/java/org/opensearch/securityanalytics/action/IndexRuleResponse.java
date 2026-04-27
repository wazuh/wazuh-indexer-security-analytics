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

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class IndexRuleResponse extends ActionResponse implements ToXContentObject {

    /** the id of the created/updated rule */
    private String id;

    /** the version of the created/updated rule */
    private Long version;

    /** REST method for the request PUT/POST */
    private RestStatus status;

    /** the Rule object of security-analytics */
    private Rule rule;

    public IndexRuleResponse(String id, Long version, RestStatus status, Rule rule) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.rule = rule;
    }

    public IndexRuleResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readLong(), sin.readEnum(RestStatus.class), Rule.readFrom(sin));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
        rule.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field(_ID, id).field(_VERSION, version);

        builder
                .startObject("rule")
                .field(Rule.CATEGORY, rule.getCategory())
                .field(Rule.LOG_SOURCE, rule.getLogSource())
                .field(Rule.TAGS, rule.getTags())
                .field(Rule.REFERENCES, rule.getReferences())
                .field(Rule.LEVEL, rule.getLevel())
                .field(Rule.FALSE_POSITIVES, rule.getFalsePositives())
                .field(Rule.STATUS, rule.getStatus())
                .field(Detector.LAST_UPDATE_TIME_FIELD, rule.getDate())
                .field(Rule.RULE, rule.getRule())
                .endObject();

        return builder.endObject();
    }

    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }

    public RestStatus getStatus() {
        return status;
    }

    public Rule getRule() {
        return rule;
    }
}
