package com.wazuh.securityanalytics.action;

import org.opensearch.action.support.WriteRequest;
import org.opensearch.rest.RestRequest;

public interface WIndexRuleRequest  {

    String getRuleId();
    WriteRequest.RefreshPolicy getRefreshPolicy();
    String getLogType();
    RestRequest.Method getMethod();
    String getRule();
    Boolean isForced();
}
