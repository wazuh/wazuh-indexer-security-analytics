package com.wazuh.securityanalytics;

import org.opensearch.core.action.ActionListener;
import com.wazuh.securityanalytics.action.WIndexRuleAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequestImpl;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;
import org.opensearch.transport.client.node.NodeClient;

public class  SecurityAnalyticsInterface {

    public static void indexRule(NodeClient client, WIndexRuleRequestImpl request, ActionListener<WIndexRuleResponse> listener) {
         client.execute(WIndexRuleAction.INSTANCE, request, listener);
    }

}
