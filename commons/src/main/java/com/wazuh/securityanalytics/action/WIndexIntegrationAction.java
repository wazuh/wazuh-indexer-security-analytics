/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

public class WIndexIntegrationAction extends ActionType<WIndexIntegrationResponse> {

    public static final WIndexIntegrationAction INSTANCE = new WIndexIntegrationAction();
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/logtype/write";

    public WIndexIntegrationAction() {
        super(NAME, WIndexIntegrationResponse::new);
    }
}
