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

/**
 * Transport action handler for indexing Wazuh rules.
 *
 * This class handles the transport-level execution of rule indexing requests,
 * converting external {@link WIndexRuleRequest} objects into internal
 * {@link IndexRuleRequest} objects and delegating to the standard rule indexing action.
 *
 * Rules are indexed with an IMMEDIATE refresh policy to ensure they are
 * available for search immediately after indexing.
 *
 * @see WIndexRuleAction
 * @see WIndexRuleRequest
 * @see WIndexRuleResponse
 */
public class WTransportIndexRuleAction extends HandledTransportAction<WIndexRuleRequest, WIndexRuleResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(WTransportIndexRuleAction.class);

    private final Client client;

    /**
     * Constructs a new WTransportIndexRuleAction.
     *
     * @param transportService the transport service for inter-node communication
     * @param client           the OpenSearch client for executing internal actions
     * @param actionFilters    filters to apply to the action execution
     */
    @Inject
    public WTransportIndexRuleAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(WIndexRuleAction.NAME, transportService, actionFilters, WIndexRuleRequest::new);
        this.client = client;
    }

    /**
     * Executes the rule indexing action.
     *
     * This method performs the following steps:
     * 1. Creates an {@link IndexRuleRequest} with the rule data from the incoming request
     * 2. Sets IMMEDIATE refresh policy to ensure the rule is searchable immediately
     * 3. Executes the indexing action through the client
     * 4. Returns the result via the provided listener
     *
     * @param task     the task associated with this action execution
     * @param request  the rule indexing request containing the rule content and metadata
     * @param listener the listener to notify upon completion or failure
     */
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
