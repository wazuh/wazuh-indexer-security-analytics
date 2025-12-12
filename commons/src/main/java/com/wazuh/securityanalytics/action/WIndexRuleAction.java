/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

public class WIndexRuleAction extends ActionType<WIndexRuleResponse> {

    public static final WIndexRuleAction INSTANCE = new WIndexRuleAction();
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/rule/write";

    public WIndexRuleAction() {
        super(NAME, WIndexRuleResponse::new);
    }
}
