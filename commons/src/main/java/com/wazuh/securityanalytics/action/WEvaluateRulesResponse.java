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

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Response containing the result of evaluating Sigma rules against an event.
 *
 * <p>The {@code resultJson} field contains a JSON string with the following structure:
 *
 * <pre>
 * {
 *   "status": "success"|"error",
 *   "rules_evaluated": N,
 *   "rules_matched": N,
 *   "matches": [
 *     {
 *       "rule_id": "...",
 *       "rule_name": "...",
 *       "severity": "...",
 *       "matched_conditions": ["..."],
 *       "tags": ["..."]
 *     }
 *   ],
 * }
 * </pre>
 *
 * @see WEvaluateRulesAction
 */
public class WEvaluateRulesResponse extends ActionResponse implements ToXContentObject {

    /** The evaluation result as a JSON string. */
    private final String resultJson;

    /**
     * Constructs a new WEvaluateRulesResponse.
     *
     * @param resultJson the evaluation result as a JSON string
     */
    public WEvaluateRulesResponse(String resultJson) {
        super();
        this.resultJson = resultJson;
    }

    /**
     * Constructs a WEvaluateRulesResponse by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WEvaluateRulesResponse(StreamInput sin) throws IOException {
        super(sin);
        this.resultJson = sin.readString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(resultJson);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.rawField(
                "result",
                new ByteArrayInputStream(resultJson.getBytes(StandardCharsets.UTF_8)),
                XContentType.JSON);
    }

    /**
     * Gets the evaluation result JSON.
     *
     * @return the result JSON string
     */
    public String getResultJson() {
        return resultJson;
    }
}
