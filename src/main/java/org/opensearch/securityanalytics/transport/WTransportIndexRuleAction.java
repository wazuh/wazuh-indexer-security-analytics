package org.opensearch.securityanalytics.transport;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

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
import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;
import org.opensearch.securityanalytics.model.FieldMappingDoc;
import org.opensearch.securityanalytics.model.Rule;
import static org.opensearch.securityanalytics.model.Rule.PRE_PACKAGED_RULES_INDEX;
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

import com.wazuh.securityanalytics.action.WIndexRuleAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;

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
        AsyncWazuhIndexRule asyncAction = new AsyncWazuhIndexRule(task, request, listener);
        asyncAction.start();
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

        void start() {
            WTransportIndexRuleAction.this.threadPool.getThreadContext().stashContext();
            
            // First, ensure the pre-packaged rules index exists with proper mappings
            ensureRuleIndexInitialized(ActionListener.wrap(
                    v -> processRule(),
                    this::onFailures
            ));
        }

        /**
         * Ensures the pre-packaged rules index exists with proper mappings.
         * This must be done before indexing any rules to avoid mapping conflicts.
         */
        private void ensureRuleIndexInitialized(ActionListener<Void> listener) {
            if (ruleIndices.ruleIndexExists(true)) {
                // Index already exists, proceed
                listener.onResponse(null);
                return;
            }
            
            // Create the index with proper mappings
            try {
                ruleIndices.initRuleIndex(new ActionListener<>() {
                    @Override
                    public void onResponse(CreateIndexResponse response) {
                        if (response.isAcknowledged()) {
                            log.info("[Wazuh] Pre-packaged rules index created with proper mappings");
                            listener.onResponse(null);
                        } else {
                            listener.onFailure(new RuntimeException("Failed to create pre-packaged rules index"));
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        // Index might already exist (race condition), check again
                        if (ruleIndices.ruleIndexExists(true)) {
                            listener.onResponse(null);
                        } else {
                            listener.onFailure(e);
                        }
                    }
                }, true); // true = prepackaged
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
            Map<String, String> fieldMappings = extractFieldsAsIdentityMappings(ruleStr);
            
            // If no fields could be extracted, try to index the rule anyway
            if (fieldMappings.isEmpty()) {
                log.debug("No field mappings extracted for log type: {}. Attempting to index rule with empty mappings.", category);
                
                try {
                    SigmaRule parsedRule = SigmaRule.fromYaml(ruleStr, true);
                    if (parsedRule == null) {
                        onFailures(new SigmaError("Failed to parse rule for log type: " + category));
                        return;
                    }
                    
                    if (parsedRule.getErrors() != null && !parsedRule.getErrors().getErrors().isEmpty()) {
                        onFailures(parsedRule.getErrors());
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
                    
                    log.debug("Extracted {} fields after conversion for log type {}: {}", 
                            fieldMappings.size(), category, fieldMappings.keySet());
                    
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
                    
                } catch (Exception e) {
                    onFailures(new SigmaError("Could not process rule for log type: " + category + ". Error: " + e.getMessage()));
                    return;
                }
            }
            
            try {
                log.debug("Using identity field mappings for log type {}: {}", category, fieldMappings);
                Rule rule = this.getRule(fieldMappings, ruleStr, category);
                if (rule == null) {
                    throw new SigmaError("Failed to parse rule");
                }
                this.indexRule(rule, fieldMappings);
            } catch (IOException | SigmaError | CompositeSigmaErrors e) {
                onFailures(e);
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
                    log.debug("SigmaRule.fromYaml returned null for rule");
                    return identityMappings;
                }
                
                if (sigmaRule.getErrors() != null && !sigmaRule.getErrors().getErrors().isEmpty()) {
                    log.warn("Rule has parsing errors: {}", sigmaRule.getErrors().getErrors());
                }
                
                QueryBackend backend = new OSQueryBackend(new HashMap<>(), true, false);
                backend.convertRule(sigmaRule);
                
                Map<String, Object> queryFields = backend.getQueryFields();
                
                if (queryFields == null || queryFields.isEmpty()) {
                    log.debug("No fields extracted from rule. This may be a keyword-only rule. Rule content:\n{}", 
                            ruleStr.substring(0, Math.min(500, ruleStr.length())));
                    return identityMappings;
                }
                
                for (String field : queryFields.keySet()) {
                    identityMappings.put(field, field);
                }
                
                log.debug("Extracted {} identity mappings from rule: {}", 
                        identityMappings.size(), identityMappings.keySet());
                        
            } catch (Exception e) {
                log.debug("Failed to extract fields from rule. Error: {}. Rule content:\n{}", 
                        e.getMessage(), ruleStr.substring(0, Math.min(500, ruleStr.length())), e);
            }
            return identityMappings;
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
            log.debug("Creating rule with queries: {} and fields: {}", queries, queryFieldNames);

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
                    log.debug("Successfully indexed rule with id: {}", indexResponse.getId());
                    // Update field mappings in the log type config index
                    // This associates the fields with the integration/category
                    updateFieldMappings(
                            rule,
                            ruleFieldMappings,
                            ActionListener.wrap(
                                    v -> {
                                        log.debug("Successfully updated field mappings for rule: {}", rule.getId());
                                        onOperation(indexResponse, rule);
                                    },
                                    e -> {
                                        log.debug("Failed to update field mappings for rule: {}", rule.getId(), e);
                                        // Still consider the rule indexed successfully
                                        onOperation(indexResponse, rule);
                                    }
                            )
                    );
                }

                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
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
                
                log.debug("Creating field mapping: {} -> {} for category: {}", 
                        fieldName, schemaFields.get(defaultSchema), rule.getCategory());
            });

            WTransportIndexRuleAction.this.logTypeService.indexFieldMappingsForWazuh(
                    fieldMappingDocs,
                    listener
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
