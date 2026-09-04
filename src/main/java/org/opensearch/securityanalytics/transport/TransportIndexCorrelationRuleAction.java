/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.RestRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleAction;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleRequest;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleResponse;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.util.CorrelationRuleIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.Locale;

public class TransportIndexCorrelationRuleAction extends HandledTransportAction<IndexCorrelationRuleRequest, IndexCorrelationRuleResponse> {

    private static final Logger log = LogManager.getLogger(TransportIndexCorrelationRuleAction.class);

    private final Client client;

    private final CorrelationRuleIndices correlationRuleIndices;

    private final ClusterService clusterService;

    @Inject
    public TransportIndexCorrelationRuleAction(
        TransportService transportService,
        Client client,
        ActionFilters actionFilters,
        ClusterService clusterService,
        CorrelationRuleIndices correlationRuleIndices
    ) {
        super(IndexCorrelationRuleAction.NAME, transportService, actionFilters, IndexCorrelationRuleRequest::new);
        this.client = client;
        this.clusterService = clusterService;
        this.correlationRuleIndices = correlationRuleIndices;
    }

    @Override
    protected void doExecute(Task task, IndexCorrelationRuleRequest request, ActionListener<IndexCorrelationRuleResponse> listener) {
        // Parsed here, not in the REST handler: the ActionFilters chain that decides whether this
        // account may write correlation rules has already run, so an unprivileged account is refused
        // with 403 whatever it sends, and a body only the client produced is a 400, not a 500.
        if (request.getCorrelationRule() == null) {
            try {
                request.setCorrelationRule(this.parseCorrelationRule(request));
            } catch (Exception e) {
                log.debug("Rejecting malformed correlation rule request body", e);
                String detail = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                listener.onFailure(
                    new OpenSearchStatusException(
                        String.format(Locale.ROOT, "Malformed correlation rule request body: %s", detail),
                        RestStatus.BAD_REQUEST
                    )
                );
                return;
            }
        }

        // Was in IndexCorrelationRuleRequest.validate(), which runs ahead of the ActionFilters chain
        // and dereferenced the name unchecked: a nameless rule became a 500 before authz was decided.
        if (!IndexCorrelationRuleRequest.isValidRuleName(request.getCorrelationRule().getName())) {
            listener.onFailure(
                new OpenSearchStatusException(
                    "Correlation rule name must be 5 to 50 characters long and may contain only letters, digits, spaces and the characters _ , - .",
                    RestStatus.BAD_REQUEST
                )
            );
            return;
        }

        AsyncIndexCorrelationRuleAction asyncAction = new AsyncIndexCorrelationRuleAction(request, listener);
        asyncAction.start();
    }

    /** Parses the correlation rule from the raw body a REST-originated request carries. */
    private CorrelationRule parseCorrelationRule(IndexCorrelationRuleRequest request) throws IOException {
        byte[] body = request.getBody();
        if (body == null || body.length == 0) {
            throw new IllegalArgumentException("Request body is required");
        }

        MediaType mediaType = request.getMediaType() != null
            ? MediaTypeRegistry.fromMediaType(request.getMediaType())
            : MediaTypeRegistry.JSON;
        if (mediaType == null) {
            throw new IllegalArgumentException(String.format(Locale.ROOT, "Unsupported Content-Type [%s]", request.getMediaType()));
        }

        // CorrelationRule reads only plain values, never named objects, so EMPTY suffices.
        try (
            XContentParser xcp = mediaType.xContent().createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, body)
        ) {
            return CorrelationRule.parse(xcp, request.getCorrelationRuleId(), null);
        }
    }

    class AsyncIndexCorrelationRuleAction {
        private final IndexCorrelationRuleRequest request;

        private final ActionListener<IndexCorrelationRuleResponse> listener;

        AsyncIndexCorrelationRuleAction(IndexCorrelationRuleRequest request, ActionListener<IndexCorrelationRuleResponse> listener) {
            this.request = request;
            this.listener = listener;
        }

        void start() {
            try {
                if (!correlationRuleIndices.correlationRuleIndexExists()) {
                    try {
                        correlationRuleIndices.initCorrelationRuleIndex(new ActionListener<>() {
                            @Override
                            public void onResponse(CreateIndexResponse response) {
                                try {
                                    onCreateMappingsResponse(response);
                                    indexCorrelationRule();
                                } catch (IOException e) {
                                    onFailures(e);
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                onFailures(e);
                            }
                        });
                    } catch (IOException e) {
                        onFailures(e);
                    }
                } else if (!IndexUtils.correlationRuleIndexUpdated) {
                    IndexUtils.updateIndexMapping(
                        CorrelationRule.CORRELATION_RULE_INDEX,
                        CorrelationRuleIndices.correlationRuleIndexMappings(),
                        clusterService.state(),
                        client.admin().indices(),
                        new ActionListener<>() {
                            @Override
                            public void onResponse(AcknowledgedResponse response) {
                                onUpdateMappingsResponse(response);
                                try {
                                    indexCorrelationRule();
                                } catch (IOException e) {
                                    onFailures(e);
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                onFailures(e);
                            }
                        },
                        false
                    );
                } else {
                    indexCorrelationRule();
                }
            } catch (IOException ex) {
                onFailures(ex);
            }
        }

        void indexCorrelationRule() throws IOException {
            IndexRequest indexRequest;
            if (request.getMethod() == RestRequest.Method.POST) {
                indexRequest = new IndexRequest(CorrelationRule.CORRELATION_RULE_INDEX).setRefreshPolicy(
                    WriteRequest.RefreshPolicy.IMMEDIATE
                )
                    .source(request.getCorrelationRule().toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .timeout(TimeValue.timeValueSeconds(60));
            } else {
                indexRequest = new IndexRequest(CorrelationRule.CORRELATION_RULE_INDEX).setRefreshPolicy(
                    WriteRequest.RefreshPolicy.IMMEDIATE
                )
                    .source(request.getCorrelationRule().toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .id(request.getCorrelationRuleId())
                    .timeout(TimeValue.timeValueSeconds(60));
            }

            client.index(indexRequest, new ActionListener<>() {
                @Override
                public void onResponse(IndexResponse response) {
                    if (response.status().equals(RestStatus.CREATED) || response.status().equals(RestStatus.OK)) {
                        CorrelationRule ruleResponse = request.getCorrelationRule();
                        ruleResponse.setId(response.getId());
                        onOperation(ruleResponse);
                    } else {
                        onFailures(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        private void onCreateMappingsResponse(CreateIndexResponse response) throws IOException {
            if (response.isAcknowledged()) {
                log.info(String.format(Locale.ROOT, "Created %s with mappings.", CorrelationRule.CORRELATION_RULE_INDEX));
                IndexUtils.correlationRuleIndexUpdated();
            } else {
                log.error(String.format(Locale.ROOT, "Create %s mappings call not acknowledged.", CorrelationRule.CORRELATION_RULE_INDEX));
                throw new OpenSearchStatusException(
                    String.format(Locale.getDefault(), "Create %s mappings call not acknowledged", CorrelationRule.CORRELATION_RULE_INDEX),
                    RestStatus.INTERNAL_SERVER_ERROR
                );
            }
        }

        private void onUpdateMappingsResponse(AcknowledgedResponse response) {
            if (response.isAcknowledged()) {
                log.info(String.format(Locale.ROOT, "Created %s with mappings.", CorrelationRule.CORRELATION_RULE_INDEX));
                IndexUtils.correlationRuleIndexUpdated();
            } else {
                log.error(String.format(Locale.ROOT, "Create %s mappings call not acknowledged.", CorrelationRule.CORRELATION_RULE_INDEX));
                throw new OpenSearchStatusException(
                    String.format(Locale.getDefault(), "Create %s mappings call not acknowledged", CorrelationRule.CORRELATION_RULE_INDEX),
                    RestStatus.INTERNAL_SERVER_ERROR
                );
            }
        }

        private void onOperation(CorrelationRule correlationRule) {
            finishHim(correlationRule, null);
        }

        private void onFailures(Exception t) {
            finishHim(null, t);
        }

        private void finishHim(CorrelationRule correlationRule, Exception t) {
            if (t != null) {
                listener.onFailure(t);
            } else {
                listener.onResponse(new IndexCorrelationRuleResponse(
                    correlationRule.getId(),
                    correlationRule.getVersion(),
                    request.getMethod() == RestRequest.Method.POST ? RestStatus.CREATED : RestStatus.OK,
                    correlationRule
                ));
            }
        }
    }
}
