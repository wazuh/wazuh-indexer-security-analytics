package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WIndexRuleAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequestImpl;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.action.IndexRuleAction;
import org.opensearch.securityanalytics.action.IndexRuleRequest;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

public class WTransportIndexRuleAction extends HandledTransportAction<WIndexRuleRequestImpl, WIndexRuleResponse>  {

    private final Client client;

    @Inject
    public WTransportIndexRuleAction(TransportService transportService, Client client, ActionFilters actionFilters,
                                    ClusterService clusterService, DetectorIndices detectorIndices,
                                    RuleIndices ruleIndices, NamedXContentRegistry xContentRegistry,
                                    LogTypeService logTypeService, Settings settings) {
        super(WIndexRuleAction.NAME, transportService, actionFilters, WIndexRuleRequestImpl::new);
        this.client = client;

    }

    @Override
    protected void doExecute(Task task, WIndexRuleRequestImpl request, ActionListener<WIndexRuleResponse> listener) {
        IndexRuleRequest ruleRequest = new IndexRuleRequest(
                request.getRuleId(),
                WriteRequest.RefreshPolicy.IMMEDIATE,
                request.getLogType(),
                RestRequest.Method.POST,
                request.getRule(),
                request.isForced()
        );
        this.client.execute(IndexRuleAction.INSTANCE, ruleRequest);
    }
}
