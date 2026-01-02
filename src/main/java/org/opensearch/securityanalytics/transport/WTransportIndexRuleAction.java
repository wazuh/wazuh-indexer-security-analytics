package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WIndexRuleAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
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

import org.opensearch.action.support.WriteRequest;
import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;
import static org.opensearch.securityanalytics.model.Rule.PRE_PACKAGED_RULES_INDEX;

public class WTransportIndexRuleAction extends HandledTransportAction<WIndexRuleRequest, WIndexRuleResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(WTransportIndexRuleAction.class);

    private final Client client;
    private final LogTypeService logTypeService;
    private final RuleIndices ruleIndices;
    private final ThreadPool threadPool;

    @Inject
    public WTransportIndexRuleAction(
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
        this.ruleIndices = ruleIndices;
    }

    @Override
    protected void doExecute(Task task, WIndexRuleRequest request, ActionListener<WIndexRuleResponse> listener) {
        AsyncIndexRule asyncAction = new AsyncIndexRule(request, listener);
        asyncAction.start();
    }

    class AsyncIndexRule {
        private final WIndexRuleRequest request;
        private final ActionListener<WIndexRuleResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();

        AsyncIndexRule(WIndexRuleRequest request, ActionListener<WIndexRuleResponse> listener) {
            this.request = request;
            this.listener = listener;
            this.response = new AtomicReference<>();
        }

        void start() {
            WTransportIndexRuleAction.this.threadPool.getThreadContext().stashContext();
            // First, ensure the pre-packaged rules index exists with proper mappings
            this.ensureRuleIndexInitialized(ActionListener.wrap(
                    v -> {
                        this.processRule();
                    },
                    e -> {
                       this.onFailures(e);
                    }
            ));
        }

        /**
         * Ensures the pre-packaged rules index exists with proper mappings.
         * This must be done before indexing any rules to avoid mapping conflicts.
         */
        private void ensureRuleIndexInitialized(ActionListener<Void> listener) {
            if (WTransportIndexRuleAction.this.ruleIndices.ruleIndexExists(true)) {
                // Index already exists, proceed
                listener.onResponse(null);
                return;
            }

            // Create the index with proper mappings
            try {
                WTransportIndexRuleAction.this.ruleIndices.initRuleIndex(new ActionListener<>() {
                    @Override
                    public void onResponse(CreateIndexResponse response) {
                        if (response.isAcknowledged()) {
                            log.info("Pre-packaged rules index created with proper mappings");
                            listener.onResponse(null);
                        } else {
                            listener.onFailure(new RuntimeException("Failed to create pre-packaged rules index"));
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        // Index might already exist (race condition), check again
                        if (WTransportIndexRuleAction.this.ruleIndices.ruleIndexExists(true)) {
                            listener.onResponse(null);
                        } else {
                            listener.onFailure(e);
                        }
                    }
                }, true);
            } catch (IOException e) {
                listener.onFailure(e);
            }
        }

        /**
         * Process the rule after ensuring the index exists.
         */
        private void processRule() {
            String category = this.request.getLogType();
            String ruleStr = this.request.getRule();

            // Extract fields from the rule and create identity mappings
            Map<String, String> fieldMappings = this.extractFieldsAsIdentityMappings(ruleStr);
            
            // If no fields could be extracted, try to index the rule anyway
            if (fieldMappings.isEmpty()) {
                try {
                    SigmaRule parsedRule = SigmaRule.fromYaml(ruleStr, true);
                    if (parsedRule == null) {
                        this.onFailures(new SigmaError("Failed to parse rule for log type: " + category));
                        return;
                    }

                    if (parsedRule.getErrors() != null && !parsedRule.getErrors().getErrors().isEmpty()) {
                        this.onFailures(parsedRule.getErrors());
                        return;
                    }

                    // Convert rule without field mappings
                    QueryBackend backend = new OSQueryBackend(new HashMap<>(), true, false);
                    List<Object> queries = backend.convertRule(parsedRule);
                    Set<String> queryFieldNames = backend.getQueryFields().keySet();
                    
                    // Create identity mappings from fields
                    for (String field : queryFieldNames) {
                        fieldMappings.put(field, field);
                    }

                    if (fieldMappings.isEmpty()) {
                        // Rule has no field-based conditions (keyword-only rule)
                        log.debug("Rule has no field-based conditions (keyword-only). Indexing with empty field mappings for log type: {}", category);
                    }

                    Rule rule = new Rule(
                            parsedRule.getId().toString(),
                            NO_VERSION,
                            parsedRule,
                            category,
                            queries,
                            new ArrayList<>(queryFieldNames),
                            ruleStr
                    );

                    this.indexRule(rule, fieldMappings);
                    return;

                } catch (IOException | SigmaConditionError | SigmaValueError e) {
                    this.onFailures(new SigmaError("Could not process rule for log type: " + category + ". Error: " + e.getMessage()));
                    return;
                }
            }
            
            try {
                Rule rule = this.getRule(fieldMappings, ruleStr, category);
                if (rule == null) {
                    throw new SigmaError("Failed to parse rule");
                }
                this.indexRule(rule, fieldMappings);
            } catch (IOException | SigmaError | CompositeSigmaErrors e) {
                this.onFailures(e);
            }
        }

        /**
         * Extracts field names from a Sigma rule and creates identity mappings.
         * Identity mapping means raw_field = ecs field (the field name stays the same).
         * This is used when the rule fields match the target index fields directly.
         */
        private Map<String, String> extractFieldsAsIdentityMappings(String ruleStr) {
            Map<String, String> identityMappings = new HashMap<>();
            try {
                SigmaRule sigmaRule = SigmaRule.fromYaml(ruleStr, true);

                if (sigmaRule == null) {
                    log.debug("SigmaRule.fromYaml returned null for rule {}", ruleStr);
                    return identityMappings;
                }

                if (sigmaRule.getErrors() != null && !sigmaRule.getErrors().getErrors().isEmpty()) {
                    log.debug("SigmaRule has errors for rule {}: {}", ruleStr, sigmaRule.getErrors().getErrors());
                    return identityMappings;
                }

                QueryBackend backend = new OSQueryBackend(new HashMap<>(), true, false);
                backend.convertRule(sigmaRule);

                Map<String, Object> queryFields = backend.getQueryFields();

                if (queryFields == null || queryFields.isEmpty()) {
                    // No fields could be extracted, might be a keyword-only rule
                    return identityMappings;
                }

                for (String field : queryFields.keySet()) {
                    identityMappings.put(field, field);
                }
                        
            } catch (IOException | SigmaError e) {
                throw new RuntimeException("Field extraction failed", e);
            }
            return identityMappings;
        }

        /**
         * Parses a Sigma rule from YAML and converts it to an OpenSearch Rule.
         * Uses the provided field mappings to transform rule fields to query fields.
         */
        private Rule getRule(Map<String, String> fieldMappings, String ruleStr, String category) throws IOException, SigmaValueError, SigmaConditionError {
            SigmaRule parsedRule = SigmaRule.fromYaml(ruleStr, true);
            if (parsedRule.getErrors() != null && !parsedRule.getErrors().getErrors().isEmpty()) {
                this.onFailures(parsedRule.getErrors());
                return null;
            }
            QueryBackend backend = new OSQueryBackend(fieldMappings, true, true);
            List<Object> queries = backend.convertRule(parsedRule);
            Set<String> queryFieldNames = backend.getQueryFields().keySet();

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

        /**
         * Indexes a Rule into the pre-packaged rules index.
         * After successful indexing, updates field mappings in the log type config index.
         */
        void indexRule(Rule rule, Map<String, String> ruleFieldMappings) throws IOException {
            IndexRequest indexRequest = new IndexRequest(PRE_PACKAGED_RULES_INDEX)
                    .id(rule.getId())
                    .source(rule.toXContent(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .timeout(TimeValue.timeValueSeconds(10));
            client.index(indexRequest, new ActionListener<>() {
                @Override
                public void onResponse(IndexResponse indexResponse) {
                    // Update field mappings in the log type config index
                    // This associates the fields with the integration/category
                    AsyncIndexRule.this.updateFieldMappings(
                            rule,
                            ruleFieldMappings,
                            ActionListener.wrap(
                                    v -> {
                                        log.info("Successfully updated field mappings for rule: {}", rule.getId());
                                        AsyncIndexRule.this.onOperation(indexResponse, rule);
                                    },
                                    e -> {
                                        log.error("Failed to update field mappings for rule: {}", rule.getId(), e);
                                        // Still consider the rule indexed successfully
                                        AsyncIndexRule.this.onOperation(indexResponse, rule);
                                    }
                            )
                    );
                }

                @Override
                public void onFailure(Exception e) {
                    AsyncIndexRule.this.listener.onFailure(e);
                }
            });
        }

        /**
         * Updates field mappings in the log type config index.
         * This creates FieldMappingDoc entries that associate rule fields with the integration/category.
         * These mappings are used by detectors to find the correct fields.
         */
        private void updateFieldMappings(Rule rule, Map<String, String> ruleFieldMappings, ActionListener<Void> listener) {
            List<FieldMappingDoc> fieldMappingDocs = new ArrayList<>();
            String defaultSchema = logTypeService.getDefaultSchemaField();

            rule.getQueryFieldNames().forEach(field -> {
                String fieldName = field.getValue();
                Map<String, String> schemaFields = new HashMap<>();

                // Use the mapped field name (which is the same in identity mapping)
                if (ruleFieldMappings.containsKey(fieldName)) {
                    schemaFields.put(defaultSchema, ruleFieldMappings.get(fieldName));
                } else {
                    // Fallback: use field name as-is for identity mapping
                    schemaFields.put(defaultSchema, fieldName);
                }

                FieldMappingDoc mappingDoc = new FieldMappingDoc(
                        fieldName,
                        schemaFields,
                        Set.of(rule.getCategory())
                );
                fieldMappingDocs.add(mappingDoc);
            });

            WTransportIndexRuleAction.this.logTypeService.indexFieldMappingsForWazuh(
                    fieldMappingDocs,
                    listener
            );
        }

        /**
         * Handler for successful rule indexing operations.
         */
        private void onOperation(IndexResponse response, Rule rule) {
            this.response.set(response);
            if (this.counter.compareAndSet(false, true)) {
                this.finishHim(rule, null);
            }
        }

        /**
         * Handler for failed operations.
         */
        private void onFailures(Exception t) {
            if (this.counter.compareAndSet(false, true)) {
                this.finishHim(null, t);
            }
        }

        /**
         * Completes the async action by sending the response or error to the listener.
         */
        private void finishHim(Rule rule, Exception t) {
            WTransportIndexRuleAction.this.threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(this.listener, () -> {
                if (t != null) {
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new WIndexRuleResponse(rule.getId(), rule.getVersion(), RestStatus.CREATED);
                }
            }));
        }
    }
}
