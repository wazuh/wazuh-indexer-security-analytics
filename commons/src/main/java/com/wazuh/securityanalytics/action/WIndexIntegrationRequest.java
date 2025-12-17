/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package com.wazuh.securityanalytics.action;

import com.wazuh.securityanalytics.model.Integration;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WIndexIntegrationRequest extends ActionRequest {

    private final String logTypeId;

    private final WriteRequest.RefreshPolicy refreshPolicy;

    private final RestRequest.Method method;

    private final Integration customLogType;

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
        this(
                sin.readString(),
                WriteRequest.RefreshPolicy.readFrom(sin),
                sin.readEnum(RestRequest.Method.class),
                Integration.readFrom(sin)
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        Matcher matcher = IS_VALID_CUSTOM_LOG_NAME.matcher(this.customLogType.getName());
        boolean find = matcher.matches();
        if (!find) {
            throw new ActionRequestValidationException();
        }
        String category = this.customLogType.getCategory();
        if (!Integration.VALID_CATEGORIES.contains(category)) {
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
