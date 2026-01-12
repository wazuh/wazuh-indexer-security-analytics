/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

/**
 * Action type for indexing Wazuh integrations (custom log types).
 * <p>
 * This action is registered under the cluster admin namespace and provides
 * the entry point for integration write operations through the transport layer.
 * <p>
 * Action name: cluster:admin/wazuh/securityanalytics/logtype/write
 *
 * @see WIndexIntegrationRequest
 * @see WIndexIntegrationResponse
 */
public class WIndexIntegrationAction extends ActionType<WIndexIntegrationResponse> {

    /** Singleton instance of this action. */
    public static final WIndexIntegrationAction INSTANCE = new WIndexIntegrationAction();

    /** The action name used for transport registration. */
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/logtype/write";

    /** Private constructor to enforce singleton pattern. */
    public WIndexIntegrationAction() {
        super(NAME, WIndexIntegrationResponse::new);
    }
}
