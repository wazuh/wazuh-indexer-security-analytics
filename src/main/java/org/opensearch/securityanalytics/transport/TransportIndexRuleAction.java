/*
 * Copyright (C) 2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.action.IndexRuleAction;
import org.opensearch.securityanalytics.action.IndexRuleRequest;
import org.opensearch.securityanalytics.action.IndexRuleResponse;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.FieldMappingDoc;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.CompositeSigmaErrors;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.opensearch.securityanalytics.model.Detector.NO_ID;
import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class TransportIndexRuleAction
        extends HandledTransportAction<IndexRuleRequest, IndexRuleResponse> {

    private static final Logger log = LogManager.getLogger(TransportIndexRuleAction.class);

    private final Client client;

    private final RuleIndices ruleIndices;

    private final DetectorIndices detectorIndices;

    private final ThreadPool threadPool;

    private final ClusterService clusterService;

    private final NamedXContentRegistry xContentRegistry;

    private final LogTypeService logTypeService;

    private final Settings settings;

    private final TimeValue indexTimeout;

    @Inject
    public TransportIndexRuleAction(
            TransportService transportService,
            Client client,
            ActionFilters actionFilters,
            ClusterService clusterService,
            DetectorIndices detectorIndices,
            RuleIndices ruleIndices,
            NamedXContentRegistry xContentRegistry,
            LogTypeService logTypeService,
            Settings settings) {
        super(IndexRuleAction.NAME, transportService, actionFilters, IndexRuleRequest::new);
        this.client = client;
        this.detectorIndices = detectorIndices;
        this.ruleIndices = ruleIndices;
        this.threadPool = ruleIndices.getThreadPool();
        this.clusterService = clusterService;
        this.xContentRegistry = xContentRegistry;
        this.logTypeService = logTypeService;
        this.settings = settings;

        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
    }

    @Override
    protected void doExecute(
            Task task, IndexRuleRequest request, ActionListener<IndexRuleResponse> listener) {
        AsyncIndexRulesAction asyncAction = new AsyncIndexRulesAction(task, request, listener);
        asyncAction.start();
    }

    class AsyncIndexRulesAction {
        private final IndexRuleRequest request;

        private final ActionListener<IndexRuleResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final AtomicInteger checker = new AtomicInteger();
        private final Task task;

        AsyncIndexRulesAction(
                Task task, IndexRuleRequest request, ActionListener<IndexRuleResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response = new AtomicReference<>();
        }

        void start() {
            TransportIndexRuleAction.this.threadPool.getThreadContext().stashContext();
            TransportIndexRuleAction.this.logTypeService.doesLogTypeExist(
                    this.request.getLogType().toLowerCase(Locale.ROOT),
                    new ActionListener<>() {
                        @Override
                        public void onResponse(Boolean exist) {
                            if (exist) {
                                try {
                                    if (!TransportIndexRuleAction.this.ruleIndices.ruleIndexExists(false)) {
                                        TransportIndexRuleAction.this.ruleIndices.initRuleIndex(
                                                new ActionListener<>() {
                                                    @Override
                                                    public void onResponse(CreateIndexResponse response) {
                                                        TransportIndexRuleAction.this.ruleIndices.onCreateMappingsResponse(
                                                                response, false);
                                                        AsyncIndexRulesAction.this.prepareRuleIndexing();
                                                    }

                                                    @Override
                                                    public void onFailure(Exception e) {
                                                        AsyncIndexRulesAction.this.onFailures(e);
                                                    }
                                                },
                                                false);
                                    } else if (!IndexUtils.customRuleIndexUpdated) {
                                        IndexUtils.updateIndexMapping(
                                                Rule.CUSTOM_RULES_INDEX,
                                                RuleIndices.ruleMappings(),
                                                TransportIndexRuleAction.this.clusterService.state(),
                                                TransportIndexRuleAction.this.client.admin().indices(),
                                                new ActionListener<>() {
                                                    @Override
                                                    public void onResponse(AcknowledgedResponse response) {
                                                        TransportIndexRuleAction.this.ruleIndices.onUpdateMappingsResponse(
                                                                response, false);
                                                        AsyncIndexRulesAction.this.prepareRuleIndexing();
                                                    }

                                                    @Override
                                                    public void onFailure(Exception e) {
                                                        AsyncIndexRulesAction.this.onFailures(e);
                                                    }
                                                },
                                                false);
                                    } else {
                                        AsyncIndexRulesAction.this.prepareRuleIndexing();
                                    }
                                } catch (IOException ex) {
                                    AsyncIndexRulesAction.this.onFailures(ex);
                                }
                            } else {
                                AsyncIndexRulesAction.this.onFailures(
                                        new OpenSearchStatusException(
                                                String.format(
                                                        "Invalid rule category %s",
                                                        AsyncIndexRulesAction.this
                                                                .request
                                                                .getLogType()
                                                                .toLowerCase(Locale.ROOT)),
                                                RestStatus.BAD_REQUEST));
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            AsyncIndexRulesAction.this.onFailures(e);
                        }
                    });
        }

        void prepareRuleIndexing() {
            String rule = this.request.getRule();
            String category = this.request.getLogType().toLowerCase(Locale.ROOT);
            TransportIndexRuleAction.this.logTypeService.getRuleFieldMappings(
                    category,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(Map<String, String> fieldMappings) {
                            try {
                                String ruleId = NO_ID;
                                SigmaRule parsedRule = SigmaRule.fromYaml(rule, true);
                                if (parsedRule.getErrors() != null
                                        && parsedRule.getErrors().getErrors().size() > 0) {
                                    AsyncIndexRulesAction.this.onFailures(parsedRule.getErrors());
                                    return;
                                }
                                QueryBackend backend = new OSQueryBackend(fieldMappings, true, true);
                                if (AsyncIndexRulesAction.this.request.getDocumentId() != null) {
                                    ruleId = UUID.randomUUID().toString();
                                } else if (AsyncIndexRulesAction.this.request.getRuleId() != null) {
                                    ruleId = AsyncIndexRulesAction.this.request.getRuleId();
                                }
                                List<Object> queries = backend.convertRule(parsedRule);
                                Set<String> queryFieldNames = backend.getQueryFields().keySet();
                                Rule ruleDoc =
                                        new Rule(
                                                ruleId,
                                                NO_VERSION,
                                                parsedRule,
                                                category,
                                                queries,
                                                new ArrayList<>(queryFieldNames),
                                                rule);
                                ruleDoc.setDocumentId(AsyncIndexRulesAction.this.request.getDocumentId());
                                ruleDoc.setSpace(AsyncIndexRulesAction.this.request.getSpace());
                                AsyncIndexRulesAction.this.indexRule(ruleDoc, fieldMappings);
                            } catch (IOException | SigmaError | CompositeSigmaErrors e) {
                                AsyncIndexRulesAction.this.onFailures(e);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            AsyncIndexRulesAction.this.onFailures(e);
                        }
                    });
        }

        void indexRule(Rule rule, Map<String, String> ruleFieldMappings) throws IOException {
            if (this.request.getMethod() == RestRequest.Method.PUT) {
                if (TransportIndexRuleAction.this.detectorIndices.detectorIndexExists()) {
                    this.searchDetectors(
                            this.request.getRuleId(),
                            new ActionListener<>() {
                                @Override
                                public void onResponse(SearchResponse response) {
                                    if (response.isTimedOut()) {
                                        AsyncIndexRulesAction.this.onFailures(
                                                new OpenSearchStatusException(
                                                        String.format(
                                                                Locale.getDefault(),
                                                                "Search request timed out. Rule with id %s cannot be updated",
                                                                rule.getId()),
                                                        RestStatus.REQUEST_TIMEOUT));
                                        return;
                                    }

                                    if (response.getHits().getTotalHits().value() > 0) {
                                        if (!AsyncIndexRulesAction.this.request.isForced()) {
                                            AsyncIndexRulesAction.this.onFailures(
                                                    new OpenSearchStatusException(
                                                            String.format(
                                                                    Locale.getDefault(),
                                                                    "Rule with id %s is actively used by detectors. Update can be forced by setting forced flag to true",
                                                                    AsyncIndexRulesAction.this.request.getRuleId()),
                                                            RestStatus.BAD_REQUEST));
                                            return;
                                        }

                                        List<Detector> detectors = new ArrayList<>();
                                        try {
                                            for (SearchHit hit : response.getHits()) {
                                                XContentParser xcp =
                                                        XContentType.JSON
                                                                .xContent()
                                                                .createParser(
                                                                        TransportIndexRuleAction.this.xContentRegistry,
                                                                        LoggingDeprecationHandler.INSTANCE,
                                                                        hit.getSourceAsString());

                                                Detector detector = Detector.docParse(xcp, hit.getId(), hit.getVersion());
                                                detectors.add(detector);
                                            }

                                            AsyncIndexRulesAction.this.updateRule(rule, ruleFieldMappings, detectors);
                                        } catch (IOException ex) {
                                            AsyncIndexRulesAction.this.onFailures(ex);
                                        }
                                    } else {
                                        try {
                                            AsyncIndexRulesAction.this.updateRule(rule, ruleFieldMappings, List.of());
                                        } catch (IOException ex) {
                                            AsyncIndexRulesAction.this.onFailures(ex);
                                        }
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    AsyncIndexRulesAction.this.onFailures(e);
                                }
                            });
                } else {
                    this.updateRule(rule, ruleFieldMappings, List.of());
                }
            } else {
                IndexRequest indexRequest =
                        new IndexRequest(Rule.CUSTOM_RULES_INDEX)
                                .setRefreshPolicy(this.request.getRefreshPolicy())
                                .source(
                                        rule.toXContent(
                                                XContentFactory.jsonBuilder(),
                                                new ToXContent.MapParams(Map.of("with_type", "true"))))
                                .timeout(TransportIndexRuleAction.this.indexTimeout);
                if (rule.getId() != NO_ID) {
                    indexRequest.id(rule.getId());
                }
                TransportIndexRuleAction.this.client.index(
                        indexRequest,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(IndexResponse response) {
                                rule.setId(response.getId());
                                AsyncIndexRulesAction.this.updateFieldMappings(
                                        rule,
                                        ruleFieldMappings,
                                        ActionListener.wrap(
                                                () -> AsyncIndexRulesAction.this.onOperation(response, rule)));
                            }

                            @Override
                            public void onFailure(Exception e) {
                                AsyncIndexRulesAction.this.onFailures(e);
                            }
                        });
            }
        }

        private void searchDetectors(String ruleId, ActionListener<SearchResponse> listener) {
            QueryBuilder queryBuilder =
                    QueryBuilders.nestedQuery(
                            "detector.inputs.detector_input.custom_rules",
                            QueryBuilders.boolQuery()
                                    .must(
                                            QueryBuilders.matchQuery(
                                                    "detector.inputs.detector_input.custom_rules.id", ruleId)),
                            ScoreMode.Avg);

            SearchRequest searchRequest =
                    new SearchRequest(Detector.DETECTORS_INDEX)
                            .source(
                                    new SearchSourceBuilder()
                                            .seqNoAndPrimaryTerm(true)
                                            .version(true)
                                            .query(queryBuilder)
                                            .size(10000))
                            .preference(Preference.PRIMARY_FIRST.type());

            TransportIndexRuleAction.this.client.search(searchRequest, listener);
        }

        private void updateDetectors(IndexResponse indexResponse, Rule rule, List<Detector> detectors) {
            for (Detector detector : detectors) {
                IndexDetectorRequest indexRequest =
                        new IndexDetectorRequest(
                                detector.getId(),
                                this.request.getRefreshPolicy(),
                                RestRequest.Method.PUT,
                                detector);
                TransportIndexRuleAction.this.client.execute(
                        IndexDetectorAction.INSTANCE,
                        indexRequest,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(IndexDetectorResponse response) {
                                if (response.getStatus() != RestStatus.OK) {
                                    AsyncIndexRulesAction.this.onFailures(
                                            new OpenSearchStatusException(
                                                    String.format(
                                                            Locale.getDefault(),
                                                            "Rule with id %s cannot be updated",
                                                            AsyncIndexRulesAction.this.request.getRuleId()),
                                                    RestStatus.INTERNAL_SERVER_ERROR));
                                }
                                AsyncIndexRulesAction.this.onComplete(indexResponse, rule, detectors.size());
                            }

                            @Override
                            public void onFailure(Exception e) {
                                AsyncIndexRulesAction.this.onFailures(e);
                            }
                        });
            }
        }

        private void updateRule(
                Rule rule, Map<String, String> ruleFieldMappings, List<Detector> detectors)
                throws IOException {
            String documentId = this.request.getDocumentId();
            String space = this.request.getSpace();

            // When documentId and space are set (content-manager PUT), the rule's internal ID
            // is a freshly generated UUID that doesn't match any existing _id. We need to
            // look up the real _id by querying document.id + space first.
            if (documentId != null && space != null) {
                this.resolveAndUpdateRule(rule, ruleFieldMappings, detectors, documentId, space);
            } else {
                String docId =
                        rule.getId() != null && !rule.getId().equals(NO_ID)
                                ? rule.getId()
                                : this.request.getRuleId();
                this.doUpdateRule(docId, rule, ruleFieldMappings, detectors);
            }
        }

        /**
         * Resolves the real _id for a rule identified by document.id + space, then delegates to
         * doUpdateRule.
         */
        private void resolveAndUpdateRule(
                Rule rule,
                Map<String, String> ruleFieldMappings,
                List<Detector> detectors,
                String documentId,
                String space) {
            QueryBuilder query =
                    QueryBuilders.nestedQuery(
                            "rule",
                            QueryBuilders.boolQuery()
                                    .filter(QueryBuilders.termQuery("rule.document.id", documentId))
                                    .filter(QueryBuilders.termQuery("rule.space", space)),
                            ScoreMode.None);
            SearchRequest searchRequest =
                    new SearchRequest(Rule.CUSTOM_RULES_INDEX)
                            .source(new SearchSourceBuilder().query(query).size(1))
                            .preference(Preference.PRIMARY_FIRST.type());

            TransportIndexRuleAction.this.client.search(
                    searchRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(SearchResponse response) {
                            String resolvedId;
                            if (response.getHits().getHits().length > 0) {
                                resolvedId = response.getHits().getHits()[0].getId();
                            } else {
                                // Fallback: no existing doc found, use rule ID
                                resolvedId =
                                        rule.getId() != null && !rule.getId().equals(NO_ID)
                                                ? rule.getId()
                                                : AsyncIndexRulesAction.this.request.getRuleId();
                            }
                            rule.setId(resolvedId);
                            try {
                                AsyncIndexRulesAction.this.doUpdateRule(
                                        resolvedId, rule, ruleFieldMappings, detectors);
                            } catch (IOException e) {
                                AsyncIndexRulesAction.this.onFailures(e);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            AsyncIndexRulesAction.this.onFailures(e);
                        }
                    });
        }

        private void doUpdateRule(
                String docId, Rule rule, Map<String, String> ruleFieldMappings, List<Detector> detectors)
                throws IOException {
            IndexRequest indexRequest =
                    new IndexRequest(Rule.CUSTOM_RULES_INDEX)
                            .setRefreshPolicy(this.request.getRefreshPolicy())
                            .source(
                                    rule.toXContent(
                                            XContentFactory.jsonBuilder(),
                                            new ToXContent.MapParams(Map.of("with_type", "true"))))
                            .id(docId)
                            .timeout(TransportIndexRuleAction.this.indexTimeout);

            TransportIndexRuleAction.this.client.index(
                    indexRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(IndexResponse response) {
                            rule.setId(response.getId());

                            AsyncIndexRulesAction.this.updateFieldMappings(
                                    rule,
                                    ruleFieldMappings,
                                    ActionListener.wrap(
                                            () -> {
                                                if (detectors.size() > 0) {
                                                    AsyncIndexRulesAction.this.updateDetectors(response, rule, detectors);
                                                } else {
                                                    AsyncIndexRulesAction.this.onOperation(response, rule);
                                                }
                                            }));
                        }

                        @Override
                        public void onFailure(Exception e) {
                            AsyncIndexRulesAction.this.onFailures(e);
                        }
                    });
        }

        private void updateFieldMappings(
                Rule rule, Map<String, String> ruleFieldMappings, ActionListener<Void> listener) {
            List<FieldMappingDoc> fieldMappingDocs = new ArrayList<>();
            rule.getQueryFieldNames()
                    .forEach(
                            field -> {
                                FieldMappingDoc mappingDoc =
                                        new FieldMappingDoc(field.getValue(), Set.of(rule.getCategory()));
                                if (ruleFieldMappings.containsKey(field.getValue())) {
                                    mappingDoc
                                            .getSchemaFields()
                                            .put(
                                                    TransportIndexRuleAction.this.logTypeService.getDefaultSchemaField(),
                                                    ruleFieldMappings.get(field.getValue()));
                                }
                                fieldMappingDocs.add(mappingDoc);
                            });
            TransportIndexRuleAction.this.logTypeService.indexFieldMappings(
                    fieldMappingDocs, ActionListener.wrap(listener::onResponse, this::onFailures));
        }

        private void onComplete(IndexResponse response, Rule rule, int target) {
            if (this.checker.incrementAndGet() == target) {
                this.onOperation(response, rule);
            }
        }

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
            TransportIndexRuleAction.this
                    .threadPool
                    .executor(ThreadPool.Names.GENERIC)
                    .execute(
                            ActionRunnable.supply(
                                    this.listener,
                                    () -> {
                                        if (t != null) {
                                            throw SecurityAnalyticsException.wrap(t);
                                        } else {
                                            return new IndexRuleResponse(
                                                    rule.getId(), rule.getVersion(), RestStatus.CREATED, rule);
                                        }
                                    }));
        }
    }
}
