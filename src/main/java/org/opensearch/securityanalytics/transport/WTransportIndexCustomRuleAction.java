package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.action.IndexRuleAction;
import org.opensearch.securityanalytics.action.IndexRuleRequest;
import org.opensearch.securityanalytics.action.IndexRuleResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import com.wazuh.securityanalytics.action.WIndexCustomRuleAction;
import com.wazuh.securityanalytics.action.WIndexCustomRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;

public class WTransportIndexCustomRuleAction extends HandledTransportAction<WIndexCustomRuleRequest, WIndexRuleResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(WTransportIndexCustomRuleAction.class);

    private final Client client;

    @Inject
    public WTransportIndexCustomRuleAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(WIndexCustomRuleAction.NAME, transportService, actionFilters, WIndexCustomRuleRequest::new);
        this.client = client;

    }

    @Override
    protected void doExecute(Task task, WIndexCustomRuleRequest request, ActionListener<WIndexRuleResponse> listener) {
        IndexRuleRequest internalRequest = new IndexRuleRequest(
                request.getRuleId(),
                request.getRefreshPolicy(),
                request.getLogType(),
                request.getMethod(),
                request.getRule(),
                request.isForced()
        );
        this.client.execute(IndexRuleAction.INSTANCE, internalRequest, new ActionListener<IndexRuleResponse>() {
            @Override
            public void onResponse(IndexRuleResponse response) {
                log.info("Successfully indexed custom rule with id: " + response.getId());
                listener.onResponse(new WIndexRuleResponse(response.getId(), response.getVersion(), response.getStatus()));
            }
            @Override
            public void onFailure(Exception e) {
                log.error("Failed to index custom rule via default action: {}", e.getMessage());
                listener.onFailure(e);
            }
        });
    }
}
