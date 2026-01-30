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
 */
public class WIndexIntegrationRequest extends ActionRequest {

    private final String logTypeId;
    private final WriteRequest.RefreshPolicy refreshPolicy;
    private final RestRequest.Method method;
    private final Integration customLogType;

    /** Pattern for validating custom log type names. */
    private static final Pattern IS_VALID_CUSTOM_LOG_NAME = Pattern.compile("[a-z0-9_-]{2,50}");

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

    public WIndexIntegrationRequest(StreamInput sin) throws IOException {
        this(sin.readString(), WriteRequest.RefreshPolicy.readFrom(sin), sin.readEnum(RestRequest.Method.class), Integration.readFrom(sin));
    }

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
        // Validation: Check if the category matches the allowed list (Title Case)
        if (!Integration.WAZUH_CATEGORIES.contains(category)) {
            validationException = addValidationError(
                    "Invalid category: '" + category + "'. Valid categories are: " + Integration.WAZUH_CATEGORIES,
                    validationException
            );
        }

        return validationException;
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
