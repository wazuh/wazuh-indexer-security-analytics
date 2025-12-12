/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

public class WIndexDetectorAction extends ActionType<WIndexDetectorResponse> {

    public static final WIndexDetectorAction INSTANCE = new WIndexDetectorAction();
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/detector/write";

    public WIndexDetectorAction() {
        super(NAME, WIndexDetectorResponse::new);
    }
}