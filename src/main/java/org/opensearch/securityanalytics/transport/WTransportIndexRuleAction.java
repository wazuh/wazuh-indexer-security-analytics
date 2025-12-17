package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WIndexRuleAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.action.IndexRuleAction;
import org.opensearch.securityanalytics.action.IndexRuleRequest;
import org.opensearch.securityanalytics.action.IndexRuleResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

public class WTransportIndexRuleAction extends HandledTransportAction<WIndexRuleRequest, WIndexRuleResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(WTransportIndexRuleAction.class);

    private final Client client;

    @Inject
    public WTransportIndexRuleAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(WIndexRuleAction.NAME, transportService, actionFilters, WIndexRuleRequest::new);
        this.client = client;

    }

    @Override
    protected void doExecute(Task task, WIndexRuleRequest request, ActionListener<WIndexRuleResponse> listener) {
        IndexRuleRequest internalRequest = new IndexRuleRequest(
                request.getRuleId(),
                WriteRequest.RefreshPolicy.IMMEDIATE,
                request.getLogType(),
                request.getMethod(),
                request.getRule(),
                request.isForced()
        );
        this.client.execute(IndexRuleAction.INSTANCE, internalRequest, new ActionListener<IndexRuleResponse>() {
            @Override
            public void onResponse(IndexRuleResponse response) {
                log.info("Successfully indexed rule with id: " + response.getId());
                listener.onResponse(new WIndexRuleResponse(response.getId(), response.getVersion(), response.getStatus()));
            }
            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }
}
