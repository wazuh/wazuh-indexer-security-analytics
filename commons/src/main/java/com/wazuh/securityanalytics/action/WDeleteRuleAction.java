package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

public class WDeleteRuleAction extends ActionType<WDeleteRuleResponse> {

    public static final WDeleteRuleAction INSTANCE = new WDeleteRuleAction();
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/rule/delete";

    public WDeleteRuleAction() {
        super(NAME, WDeleteRuleResponse::new);
    }
}