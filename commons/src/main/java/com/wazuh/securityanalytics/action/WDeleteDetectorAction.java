package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

public class WDeleteDetectorAction extends ActionType<WDeleteDetectorResponse> {

    public static final WDeleteDetectorAction INSTANCE = new WDeleteDetectorAction();
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/detector/delete";

    public WDeleteDetectorAction() {
        super(NAME, WDeleteDetectorResponse::new);
    }
}