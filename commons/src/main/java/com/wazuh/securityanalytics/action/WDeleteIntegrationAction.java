package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

public class WDeleteIntegrationAction extends ActionType<WDeleteIntegrationResponse> {

    public static final WDeleteIntegrationAction INSTANCE = new WDeleteIntegrationAction();
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/logtype/delete";

    public WDeleteIntegrationAction() {
        super(NAME, WDeleteIntegrationResponse::new);
    }
}
