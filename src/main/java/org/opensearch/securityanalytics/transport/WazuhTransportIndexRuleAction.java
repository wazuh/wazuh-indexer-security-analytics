package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WIndexRuleAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.FieldMappingDoc;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.CompositeSigmaErrors;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;
import static org.opensearch.securityanalytics.model.Rule.PRE_PACKAGED_RULES_INDEX;

public class WazuhTransportIndexRuleAction extends HandledTransportAction<WIndexRuleRequest, WIndexRuleResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(WazuhTransportIndexRuleAction.class);

    private final Client client;
    private final LogTypeService logTypeService;
    private final ThreadPool threadPool;

    @Inject
    public WazuhTransportIndexRuleAction(
            TransportService transportService,
            Client client,
            ActionFilters actionFilters,
            LogTypeService logTypeService,
            RuleIndices ruleIndices
    ) {
        super(WIndexRuleAction.NAME, transportService, actionFilters, WIndexRuleRequest::new);
        this.client = client;
        this.threadPool = ruleIndices.getThreadPool();
        this.logTypeService = logTypeService;
    }

    @Override
    protected void doExecute(Task task, WIndexRuleRequest request, ActionListener<WIndexRuleResponse> listener) {
        AsyncWazuhIndexRule asyncAction = new AsyncWazuhIndexRule(task, request, listener);
        asyncAction.execute();
    }

    class AsyncWazuhIndexRule {
        private final WIndexRuleRequest request;
        private final ActionListener<WIndexRuleResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        AsyncWazuhIndexRule(Task task, WIndexRuleRequest request, ActionListener<WIndexRuleResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;
            this.response = new AtomicReference<>();
        }

        void execute() {
            WazuhTransportIndexRuleAction.this.threadPool.getThreadContext().stashContext();
            String category = this.request.getLogType();
            String ruleStr = this.request.getRule();
            WazuhTransportIndexRuleAction.this.logTypeService.getFieldMappingsByLogType(
                    category,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(List<FieldMappingDoc> fieldMappingDocs) {
                            Map<String, String> fieldMappings = new HashMap<>(fieldMappingDocs.size());
                            fieldMappingDocs.forEach( e -> {
                                fieldMappings.put(e.getRawField(), e.getSchemaFields().get(logTypeService.getDefaultSchemaField()));
                            });
                            if (fieldMappings.isEmpty()) {
                                onFailures(new SigmaError("No field mappings found for log type: " + category));
                            } else {
                                try {
                                    Rule rule = getRule(fieldMappings, ruleStr, category);
                                    if (rule == null) {
                                        throw new SigmaError("Failed to parse rule");
                                    }
                                    indexRule(rule, fieldMappings);
                                } catch (IOException | SigmaError | CompositeSigmaErrors e) {
                                    onFailures(e);
                                }
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    }
            );
        }

        private Rule getRule(Map<String, String> fieldMappings, String ruleStr, String category) throws IOException, SigmaValueError, SigmaConditionError {
            SigmaRule parsedRule = SigmaRule.fromYaml(ruleStr, true);
            if (parsedRule.getErrors() != null && !parsedRule.getErrors().getErrors().isEmpty()) {
                onFailures(parsedRule.getErrors());
                return null;
            }
            QueryBackend backend = new OSQueryBackend(fieldMappings, true, true);
            List<Object> queries = backend.convertRule(parsedRule);
            Set<String> queryFieldNames = backend.getQueryFields().keySet();
            log.info("[TEST] Creating rule with queries: " + queries.toString() + " and fields: " + queryFieldNames.toString());

            return new Rule(
                    parsedRule.getId().toString(),
                    NO_VERSION,
                    parsedRule,
                    category,
                    queries,
                    new ArrayList<>(queryFieldNames),
                    ruleStr
            );
        }

        void indexRule(Rule rule, Map<String, String> ruleFieldMappings) throws IOException {
            IndexRequest indexRequest = new IndexRequest(PRE_PACKAGED_RULES_INDEX)
                    .id(rule.getId())
                    .source(rule.toXContent(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                    .timeout(TimeValue.timeValueSeconds(10));
            client.index(indexRequest, new ActionListener<>() {
                @Override
                public void onResponse(IndexResponse indexResponse) {
                    log.info("Successfully indexed rule with id: " + indexResponse.getId());
                    updateFieldMappings(
                            rule,
                            ruleFieldMappings,
                            ActionListener.wrap(() -> onOperation(indexResponse, rule))
                    );
                    listener.onResponse(new WIndexRuleResponse(indexResponse.getId(), indexResponse.getVersion(), indexResponse.status()));
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to index rule with id: " + rule.getId(), e);
                    listener.onFailure(e);
                }
            });
        }

        private void updateFieldMappings(Rule rule, Map<String, String> ruleFieldMappings, ActionListener<Void> listener) {
            List<FieldMappingDoc> fieldMappingDocs = new ArrayList<>();
            rule.getQueryFieldNames().forEach(field -> {
                FieldMappingDoc mappingDoc = new FieldMappingDoc(field.getValue(), Set.of(rule.getCategory()));
                if (ruleFieldMappings.containsKey(field.getValue())) {
                    mappingDoc.getSchemaFields().put(logTypeService.getDefaultSchemaField(), ruleFieldMappings.get(field.getValue()));
                }
                fieldMappingDocs.add(mappingDoc);
            });
            WazuhTransportIndexRuleAction.this.logTypeService.indexFieldMappings(
                    fieldMappingDocs,
                    ActionListener.wrap(listener::onResponse, this::onFailures)
            );
        }

        // Handlers
        private void onOperation(IndexResponse response, Rule rule) {
            this.response.set(response);
            if (this.counter.compareAndSet(false, true)) {
                this.finishHim(rule, null);
            }
        }

        private void onFailures(Exception t) {
            if (this.counter.compareAndSet(false, true)) {
                this.finishHim(null, t);
            }
        }

        private void finishHim(Rule rule, Exception t) {
            WazuhTransportIndexRuleAction.this.threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(this.listener, () -> {
                if (t != null) {
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new WIndexRuleResponse(rule.getId(), rule.getVersion(), RestStatus.CREATED);
                }
            }));
        }
    }
}
