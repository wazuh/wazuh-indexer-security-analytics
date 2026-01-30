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

import static org.opensearch.action.ValidateActions.addValidationError;

/**
 * Request for indexing a Wazuh integration (custom log type).
 * <p>
 * This request contains all the information needed to create or update an integration,
 * including the log type ID, refresh policy, HTTP method, and the integration data.
 * <p>
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
        ActionRequestValidationException validationException = null;

        Matcher matcher = IS_VALID_CUSTOM_LOG_NAME.matcher(this.customLogType.getName());
        if (!matcher.matches()) {
            validationException = addValidationError(
                    "Invalid integration name '" + this.customLogType.getName() + "'. Must match pattern: [a-z0-9_-]{2,50}",
                    validationException
            );
        }

        String category = this.customLogType.getCategory();
        if (!Integration.WAZUH_CATEGORIES.contains(category)) {
            validationException = addValidationError(
                    "Invalid category: '" + category + "'. Valid categories are: " + Integration.WAZUH_CATEGORIES,
                    validationException
            );
        }

        return validationException;
    }

    /**
     * Serializes this request to the given stream output for inter-node communication.
     *
     * @param out the stream output to write to
     * @throws IOException if an I/O error occurs during serialization
     */
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.logTypeId);
        this.refreshPolicy.writeTo(out);
        out.writeEnum(this.method);
        this.customLogType.writeTo(out);
    }

    /**
     * Gets the unique identifier for the log type.
     *
     * @return the log type ID
     */
    public String getLogTypeId() {
        return this.logTypeId;
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
     * Gets the integration (custom log type) data to be indexed.
     *
     * @return the integration instance
     */
    public Integration getCustomLogType() {
        return this.customLogType;
    }
}
