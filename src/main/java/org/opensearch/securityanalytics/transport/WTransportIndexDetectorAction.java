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

public class WTransportIndexDetectorAction extends HandledTransportAction<WIndexDetectorRequest, WIndexDetectorResponse> implements SecureTransportAction{
    private final Client client;
    private static final Logger log = LogManager.getLogger(WTransportIndexDetectorAction.class);

    @Inject
    public WTransportIndexDetectorAction(TransportService transportService,
                                            Client client,
                                            ActionFilters actionFilters) {
        super(WIndexDetectorAction.NAME, transportService, actionFilters, WIndexDetectorRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, WIndexDetectorRequest request, ActionListener<WIndexDetectorResponse> listener) {
        // Create detector for this Integration
        Detector detector = DetectorFactory.createDetector(request.getLogTypeName(), request.getCategory(), request.getRules());
        IndexDetectorRequest indexDetectorRequest = new IndexDetectorRequest(
                detector.getId(),
                request.getRefreshPolicy(),
                RestRequest.Method.POST,
                detector);
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
