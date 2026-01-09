package org.opensearch.securityanalytics.transport;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
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
import org.opensearch.action.support.WriteRequest;
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
public class WTransportIndexRuleAction extends HandledTransportAction<WIndexRuleRequest, WIndexRuleResponse>
    implements
        SecureTransportAction {
    private static final Logger log = LogManager.getLogger(WTransportIndexRuleAction.class);

    private final Client client;
    private final LogTypeService logTypeService;
    private final RuleIndices ruleIndices;
    private final ThreadPool threadPool;

    /**
     * Constructs a new WTransportIndexRuleAction.
     *
     * @param transportService the transport service for inter-node communication
     * @param client           the OpenSearch client for executing internal actions
     * @param actionFilters    filters to apply to the action execution
     */
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
         * Parses the rule once and converts it in a single pass to extract fields and queries.
         */
        private void processRule() {
            String category = this.request.getLogType();
            String ruleStr = this.request.getRule();

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

                List<Object> queries = Collections.emptyList();
                Set<String> queryFieldNames = Collections.emptySet();
                Map<String, String> fieldMappings = new HashMap<>();

                try {
                    // Single-pass conversion to get both queries and field names
                    QueryBackend backend = new OSQueryBackend(Collections.emptyMap(), true, false);
                    queries = backend.convertRule(parsedRule);
                    queryFieldNames = backend.getQueryFields().keySet();

                    // Build identity mappings (field -> field) from discovered fields
                    for (String field : queryFieldNames) {
                        fieldMappings.put(field, field);
                    }
                } catch (IOException | SigmaConditionError | SigmaValueError e) {
                    // Log warning but continue - rule can still be indexed with empty queries/fields
                    log.warn("Failed to convert rule for log type {}: {}. Indexing with empty field mappings.", category, e.getMessage());
                }

                if (fieldMappings.isEmpty()) {
                    // Rule has no field-based conditions (keyword-only rule) or conversion failed
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

            } catch (IOException e) {
                this.onFailures(new SigmaError("Could not process rule for log type: " + category + ". Error: " + e.getMessage()));
            }
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
