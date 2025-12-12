package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WIndexDetectorAction;
import com.wazuh.securityanalytics.action.WIndexDetectorRequest;
import com.wazuh.securityanalytics.action.WIndexDetectorResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
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

import java.util.ArrayList;

public class WTransportIndexDetectorAction extends HandledTransportAction<WIndexDetectorRequest, WIndexDetectorResponse> implements SecureTransportAction{
    private final Client client;

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
        Detector integrationDetector = DetectorFactory.createDetector(request.getLogTypeName(), request.getRules());
        IndexDetectorRequest indexDetectorRequest = new IndexDetectorRequest(
                integrationDetector.getId(),
                request.getRefreshPolicy(),
                RestRequest.Method.POST,
                integrationDetector);
        client.execute(IndexDetectorAction.INSTANCE, indexDetectorRequest);
    }
}
