package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

public class WDeleteCustomRuleAction extends ActionType<WDeleteRuleResponse> {

    public static final WDeleteCustomRuleAction INSTANCE = new WDeleteCustomRuleAction();
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/rule/custom/delete";

    public WDeleteCustomRuleAction() {
        super(NAME, WDeleteRuleResponse::new);
    }
}