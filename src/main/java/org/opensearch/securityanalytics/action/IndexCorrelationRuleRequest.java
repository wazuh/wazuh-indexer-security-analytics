/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.opensearch.securityanalytics.model.CorrelationRule;

/**
 * Transport request to create or update a correlation rule. A request from the REST layer carries
 * the raw body with the rule unset, for {@code TransportIndexCorrelationRuleAction} to parse once
 * privileges have been evaluated.
 */
public class IndexCorrelationRuleRequest extends ActionRequest {

    private String correlationRuleId;

    private CorrelationRule correlationRule;

    private RestRequest.Method method;

    /** Raw request body and its media type, both null when the rule was supplied parsed. */
    private final byte[] body;

    private final String mediaType;

    private static final Pattern IS_VALID_RULE_NAME = Pattern.compile("[a-zA-Z0-9 _,-.]{5,50}");

    public IndexCorrelationRuleRequest(String correlationRuleId, CorrelationRule correlationRule, RestRequest.Method method) {
        super();
        this.correlationRuleId = correlationRuleId;
        this.correlationRule = correlationRule;
        this.method = method;
        this.body = null;
        this.mediaType = null;
    }

    /** Builds a request whose rule the transport action still has to parse from the raw body. */
    public IndexCorrelationRuleRequest(String correlationRuleId, RestRequest.Method method, byte[] body, String mediaType) {
        super();
        this.correlationRuleId = correlationRuleId;
        this.correlationRule = null;
        this.method = method;
        this.body = body;
        this.mediaType = mediaType;
    }

    public IndexCorrelationRuleRequest(StreamInput sin) throws IOException {
        super();
        this.correlationRuleId = sin.readString();
        this.correlationRule = sin.readBoolean() ? CorrelationRule.readFrom(sin) : null;
        this.method = sin.readEnum(RestRequest.Method.class);
        this.body = sin.readBoolean() ? sin.readByteArray() : null;
        this.mediaType = sin.readOptionalString();
    }

    @Override
    public ActionRequestValidationException validate() {
        // validate() runs ahead of the ActionFilters chain, so nothing that inspects the body belongs
        // here. The name is checked by the transport action, after privileges have been evaluated.
        return null;
    }

    /** @return true if the rule name is present and well-formed */
    public static boolean isValidRuleName(String name) {
        if (name == null) {
            return false;
        }
        Matcher matcher = IS_VALID_RULE_NAME.matcher(name);
        return matcher.matches();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(correlationRuleId);
        // Mirrors the StreamInput constructor field for field; it previously omitted the method.
        out.writeBoolean(correlationRule != null);
        if (correlationRule != null) {
            correlationRule.writeTo(out);
        }
        out.writeEnum(method);
        out.writeBoolean(body != null);
        if (body != null) {
            out.writeByteArray(body);
        }
        out.writeOptionalString(mediaType);
    }

    public String getCorrelationRuleId() {
        return correlationRuleId;
    }

    /** @return the rule, or null while the raw body has not been parsed yet */
    public CorrelationRule getCorrelationRule() {
        return correlationRule;
    }

    public void setCorrelationRule(CorrelationRule correlationRule) {
        this.correlationRule = correlationRule;
    }

    public byte[] getBody() {
        return body;
    }

    public String getMediaType() {
        return mediaType;
    }

    public RestRequest.Method getMethod() {
        return method;
    }
}
