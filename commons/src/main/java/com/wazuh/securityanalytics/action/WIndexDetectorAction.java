/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

/**
 * Action type for indexing Wazuh detectors.
 * <p>
 * This action is registered under the cluster admin namespace and provides
 * the entry point for detector write operations through the transport layer.
 * <p>
 * Action name: cluster:admin/wazuh/securityanalytics/detector/write
 *
 * @see WIndexDetectorRequest
 * @see WIndexDetectorResponse
 */
public class WIndexDetectorAction extends ActionType<WIndexDetectorResponse> {

    /** Singleton instance of this action. */
    public static final WIndexDetectorAction INSTANCE = new WIndexDetectorAction();

    /** The action name used for transport registration. */
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/detector/write";

    /** Private constructor to enforce singleton pattern. */
    public WIndexDetectorAction() {
        super(NAME, WIndexDetectorResponse::new);
    }
}
