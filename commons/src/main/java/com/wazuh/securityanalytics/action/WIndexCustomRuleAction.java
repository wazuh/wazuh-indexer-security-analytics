/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

public class WIndexCustomRuleAction extends ActionType<WIndexRuleResponse> {

    public static final WIndexCustomRuleAction INSTANCE = new WIndexCustomRuleAction();
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/rule/custom/write";

    public WIndexCustomRuleAction() {
        super(NAME, WIndexRuleResponse::new);
    }
}
