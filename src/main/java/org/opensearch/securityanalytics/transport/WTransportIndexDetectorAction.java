package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WIndexDetectorAction;
import com.wazuh.securityanalytics.action.WIndexDetectorRequest;
import com.wazuh.securityanalytics.action.WIndexDetectorResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.DetectorFactory;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

/**
 * Transport action handler for indexing Wazuh detectors.
 *
 * This class handles the transport-level execution of detector indexing requests,
 * converting external {@link WIndexDetectorRequest} objects into internal
 * {@link IndexDetectorRequest} objects and delegating to the standard detector indexing action.
 *
 * The action uses {@link DetectorFactory} to create detector instances from the provided
 * log type name, category, and rules before persisting them.
 *
 * @see WIndexDetectorAction
 * @see WIndexDetectorRequest
 * @see WIndexDetectorResponse
 * @see DetectorFactory
 */
public class WTransportIndexDetectorAction extends HandledTransportAction<WIndexDetectorRequest, WIndexDetectorResponse>
    implements
        SecureTransportAction {
    private final Client client;
    private static final Logger log = LogManager.getLogger(WTransportIndexDetectorAction.class);

    /**
     * Constructs a new WTransportIndexDetectorAction.
     *
     * @param transportService the transport service for inter-node communication
     * @param client           the OpenSearch client for executing internal actions
     * @param actionFilters    filters to apply to the action execution
     */
    @Inject
    public WTransportIndexDetectorAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(WIndexDetectorAction.NAME, transportService, actionFilters, WIndexDetectorRequest::new);
        this.client = client;
    }

    /**
     * Executes the detector indexing action.
     *
     * This method performs the following steps:
     * 1. Creates a new {@link Detector} using {@link DetectorFactory} with the log type, category, and rules
     * 2. Sets the detector ID from the request
     * 3. Wraps it in an {@link IndexDetectorRequest} with PUT method
     * 4. Executes the indexing action through the client
     * 5. Returns the result via the provided listener
     *
     * @param task     the task associated with this action execution
     * @param request  the detector indexing request containing log type, category, and rules
     * @param listener the listener to notify upon completion or failure
     */
    @Override
    protected void doExecute(Task task, WIndexDetectorRequest request, ActionListener<WIndexDetectorResponse> listener) {
        // Create detector for this Integration
        Detector detector = DetectorFactory.createDetector(request.getLogTypeName(), request.getCategory(), request.getRules());
        detector.setId(request.getDetectorId());
        IndexDetectorRequest indexDetectorRequest = new IndexDetectorRequest(
            detector.getId(),
            request.getRefreshPolicy(),
            RestRequest.Method.PUT,
            detector
        );
        this.client.execute(IndexDetectorAction.INSTANCE, indexDetectorRequest, new ActionListener<>() {
            @Override
            public void onResponse(IndexDetectorResponse response) {
                log.info("Successfully indexed detector with id: {}", response.getId());
                listener.onResponse(new WIndexDetectorResponse(response.getId(), response.getVersion()));
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }
}
