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
 * Request for indexing a Wazuh integration (log type).
 * <p>
 * This request contains all the information needed to create or update an integration,
 * including the integration ID, refresh policy, HTTP method, and the integration data.
 * <p>
 * The integration name must match the pattern [a-z0-9_-]{2,50} and the category
 * must be one of the valid Wazuh categories defined in {@link Integration#LOG_CATEGORIES}.
 *
 * @see WIndexIntegrationAction
 * @see WIndexIntegrationResponse
 * @see Integration
 */
public class WIndexIntegrationRequest extends ActionRequest {

    private final String id;

    private final WriteRequest.RefreshPolicy refreshPolicy;

    private final RestRequest.Method method;

    private final Integration integration;

    /** Pattern for validating log type names. */
    private static final Pattern IS_VALID_NAME = Pattern.compile("[a-z0-9_-]{2,50}");

    /**
     * Constructs a new WIndexIntegrationRequest.
     *
     * @param id     the unique identifier for the integration
     * @param refreshPolicy the refresh policy for the index operation
     * @param method        the HTTP method (PUT for update, POST for create)
     * @param integration the integration data to index
     */
    public WIndexIntegrationRequest(
        String id,
        WriteRequest.RefreshPolicy refreshPolicy,
        RestRequest.Method method,
        Integration integration
    ) {
        super();
        this.id = id;
        this.refreshPolicy = refreshPolicy;
        this.method = method;
        this.integration = integration;
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

    /**
     * Validates the integration request by checking the integration name format and category.
     *
     * <p>The validation ensures:
     * <ul>
     *   <li>The integration name matches the pattern [a-z0-9_-]{2,50}</li>
     *   <li>The category is one of the valid Wazuh categories</li>
     * </ul>
     *
     * @return null if validation passes, otherwise throws an exception
     * @throws ActionRequestValidationException if the name or category is invalid
     */
    @Override
    public ActionRequestValidationException validate() {
        Matcher matcher = IS_VALID_NAME.matcher(this.integration.getName());
        boolean find = matcher.matches();
        if (!find) {
            throw new ActionRequestValidationException();
        }
        String category = this.integration.getCategory();
        if (!Integration.LOG_CATEGORIES.contains(category)) {
            throw new ActionRequestValidationException();
        }
        return null;
    }

    /**
     * Serializes this request to the given stream output for internode communication.
     *
     * @param out the stream output to write to
     * @throws IOException if an I/O error occurs during serialization
     */
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        this.refreshPolicy.writeTo(out);
        out.writeEnum(this.method);
        this.integration.writeTo(out);
    }

    /**
     * Gets the unique identifier for the integration.
     *
     * @return the integration ID
     */
    public String getId() {
        return this.id;
    }

    /**
     * Gets the refresh policy for the index operation.
     *
     * @return the refresh policy
     */
    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return this.refreshPolicy;
    }

    /**
     * Gets the HTTP method for the request.
     *
     * @return the HTTP method (PUT for update, POST for create)
     */
    public RestRequest.Method getMethod() {
        return this.method;
    }

    /**
     * Gets the integration (log type) data to be indexed.
     *
     * @return the integration instance
     */
    public Integration getIntegration() {
        return this.integration;
    }
}
