/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package com.wazuh.securityanalytics.action;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.wazuh.securityanalytics.model.Integration;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;

/**
 * Request for indexing a Wazuh integration (custom log type).
 *
 * This request contains all the information needed to create or update an integration,
 * including the log type ID, refresh policy, HTTP method, and the integration data.
 *
 * The integration name must match the pattern [a-z0-9_-]{2,50} and the category
 * must be one of the valid Wazuh categories defined in {@link Integration#WAZUH_CATEGORIES}.
 *
 * @see WIndexIntegrationAction
 * @see WIndexIntegrationResponse
 * @see Integration
 */
public class WIndexIntegrationRequest extends ActionRequest {

    private final String logTypeId;

    private final WriteRequest.RefreshPolicy refreshPolicy;

    private final RestRequest.Method method;

    private final Integration customLogType;

    /** Pattern for validating custom log type names. */
    private static final Pattern IS_VALID_CUSTOM_LOG_NAME = Pattern.compile("[a-z0-9_-]{2,50}");

    /**
     * Constructs a new WIndexIntegrationRequest.
     *
     * @param logTypeId     the unique identifier for the log type
     * @param refreshPolicy the refresh policy for the index operation
     * @param method        the HTTP method (PUT for update, POST for create)
     * @param customLogType the integration data to index
     */
    public WIndexIntegrationRequest(
        String logTypeId,
        WriteRequest.RefreshPolicy refreshPolicy,
        RestRequest.Method method,
        Integration customLogType
    ) {
        super();
        this.logTypeId = logTypeId;
        this.refreshPolicy = refreshPolicy;
        this.method = method;
        this.customLogType = customLogType;
    }

    /**
     * Constructs a WIndexIntegrationRequest by deserializing from a stream.
     *
     * @param sin the stream input to read from
     * @throws IOException if an I/O error occurs during deserialization
     */
    public WIndexIntegrationRequest(StreamInput sin) throws IOException {
        this(sin.readString(), WriteRequest.RefreshPolicy.readFrom(sin), sin.readEnum(RestRequest.Method.class), Integration.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        Matcher matcher = IS_VALID_CUSTOM_LOG_NAME.matcher(this.customLogType.getName());
        boolean find = matcher.matches();
        if (!find) {
            throw new ActionRequestValidationException();
        }
        String category = this.customLogType.getCategory();
        if (!Integration.WAZUH_CATEGORIES.contains(category)) {
            throw new ActionRequestValidationException();
        }
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.logTypeId);
        this.refreshPolicy.writeTo(out);
        out.writeEnum(this.method);
        this.customLogType.writeTo(out);
    }

    public String getLogTypeId() {
        return this.logTypeId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return this.refreshPolicy;
    }

    public RestRequest.Method getMethod() {
        return this.method;
    }

    public Integration getCustomLogType() {
        return this.customLogType;
    }
}
