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
package org.opensearch.securityanalytics.logtype;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActiveShardCount;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.io.Streams;
import org.opensearch.common.util.set.Sets;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.aggregations.bucket.terms.Terms;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.FieldMappingDoc;
import org.opensearch.securityanalytics.model.LogType;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.transport.client.Client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.model.FieldMappingDoc.LOG_TYPES;
import static org.opensearch.securityanalytics.model.FieldMappingDoc.WAZUH_INTEGRATIONS;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.DEFAULT_MAPPING_SCHEMA;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.maxSystemIndexReplicas;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.minSystemIndexReplicas;

/** */
public class LogTypeService {

    private static final Logger logger = LogManager.getLogger(LogTypeService.class);

    public static final String LOG_TYPE_INDEX = ".opensearch-sap-log-types-config";

    public static final String LOG_TYPE_INDEX_MAPPING_FILE = "mappings/log_type_config_mapping.json";

    public static final String LOG_TYPE_MAPPING_VERSION_META_FIELD = "schema_version";

    public static final int MAX_LOG_TYPE_COUNT = 100;

    private static volatile boolean isConfigIndexInitialized;

    private final Client client;

    private final ClusterService clusterService;

    private final NamedXContentRegistry xContentRegistry;

    private final BuiltinLogTypeLoader builtinLogTypeLoader;

    private String defaultSchemaField;

    public int logTypeMappingVersion;

    @Inject
    public LogTypeService(
            Client client,
            ClusterService clusterService,
            NamedXContentRegistry xContentRegistry,
            BuiltinLogTypeLoader builtinLogTypeLoader) {
        this.client = client;
        this.clusterService = clusterService;
        this.xContentRegistry = xContentRegistry;
        this.builtinLogTypeLoader = builtinLogTypeLoader;

        this.defaultSchemaField = DEFAULT_MAPPING_SCHEMA.get(clusterService.getSettings());
        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        DEFAULT_MAPPING_SCHEMA, newDefaultSchema -> this.defaultSchemaField = newDefaultSchema);
        this.setLogTypeMappingVersion();
    }

    public void getAllLogTypes(ActionListener<List<String>> listener) {
        this.ensureConfigIndexIsInitialized(
                ActionListener.wrap(
                        e -> {
                            String field = WAZUH_INTEGRATIONS;
                            // Enable OpenSearch's log types for testing environments.
                            if (this.isLoadBuiltinLogTypesEnabled()) {
                                field = LOG_TYPES;
                            }
                            SearchRequest searchRequest = new SearchRequest(LOG_TYPE_INDEX);
                            searchRequest.source(
                                    new SearchSourceBuilder()
                                            .aggregation(
                                                    new TermsAggregationBuilder("logTypes")
                                                            .field(field)
                                                            .size(MAX_LOG_TYPE_COUNT)));
                            searchRequest.preference(Preference.PRIMARY_FIRST.type());
                            this.client.search(
                                    searchRequest,
                                    ActionListener.delegateFailure(
                                            listener,
                                            (delegatedListener, searchResponse) -> {
                                                List<String> logTypes = new ArrayList<>();
                                                Terms termsAgg = searchResponse.getAggregations().get("logTypes");
                                                for (Terms.Bucket bucket : termsAgg.getBuckets()) {
                                                    logTypes.add(bucket.getKeyAsString());
                                                }
                                                delegatedListener.onResponse(logTypes);
                                            }));
                        },
                        listener::onFailure));
    }

    public void getAllLogTypesMetadata(ActionListener<List<String>> listener) {
        this.ensureConfigIndexIsInitialized(
                ActionListener.wrap(
                        e -> {
                            BoolQueryBuilder queryBuilder =
                                    QueryBuilders.boolQuery().must(QueryBuilders.existsQuery("space"));
                            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                            searchSourceBuilder.query(queryBuilder);
                            searchSourceBuilder.fetchSource(true);
                            searchSourceBuilder.size(10000);
                            SearchRequest searchRequest = new SearchRequest();
                            searchRequest.indices(LogTypeService.LOG_TYPE_INDEX);
                            searchRequest.source(searchSourceBuilder);
                            searchRequest.preference("_primary");
                            this.client.search(
                                    searchRequest,
                                    ActionListener.delegateFailure(
                                            listener,
                                            (delegatedListener, searchResponse) -> {
                                                List<String> logTypes = new ArrayList<>();
                                                SearchHit[] hits = searchResponse.getHits().getHits();

                                                for (SearchHit hit : hits) {
                                                    Map<String, Object> source = hit.getSourceAsMap();
                                                    logTypes.add(source.get("name").toString());
                                                }
                                                delegatedListener.onResponse(logTypes);
                                            }));
                        },
                        listener::onFailure));
    }

    public void doesLogTypeExist(String logType, ActionListener<Boolean> listener) {
        this.ensureConfigIndexIsInitialized(
                ActionListener.wrap(
                        e -> {
                            BoolQueryBuilder queryBuilder =
                                    QueryBuilders.boolQuery().must(QueryBuilders.matchQuery("name", logType));
                            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                            searchSourceBuilder.query(queryBuilder);
                            searchSourceBuilder.fetchSource(true);
                            searchSourceBuilder.size(10000);
                            SearchRequest searchRequest = new SearchRequest();
                            searchRequest.indices(LogTypeService.LOG_TYPE_INDEX);
                            searchRequest.source(searchSourceBuilder);
                            searchRequest.preference("_primary");
                            this.client.search(
                                    searchRequest,
                                    ActionListener.delegateFailure(
                                            listener,
                                            (delegatedListener, searchResponse) -> {
                                                SearchHit[] hits = searchResponse.getHits().getHits();
                                                delegatedListener.onResponse(hits.length > 0);
                                            }));
                        },
                        listener::onFailure));
    }

    public void searchLogTypes(SearchRequest request, ActionListener<SearchResponse> listener) {
        this.ensureConfigIndexIsInitialized(
                ActionListener.wrap(
                        e -> {
                            BoolQueryBuilder queryBuilder =
                                    QueryBuilders.boolQuery().must(QueryBuilders.existsQuery("space"));
                            if (request.source().query() != null) {
                                queryBuilder.must(request.source().query());
                            }

                            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                            searchSourceBuilder.query(queryBuilder);
                            searchSourceBuilder.fetchSource(true);
                            searchSourceBuilder.size(10000);
                            SearchRequest searchRequest = new SearchRequest();
                            searchRequest.indices(LogTypeService.LOG_TYPE_INDEX);
                            searchRequest.source(searchSourceBuilder);
                            searchRequest.preference("_primary");
                            this.client.search(
                                    searchRequest,
                                    ActionListener.delegateFailure(
                                            listener,
                                            (delegatedListener, searchResponse) -> {
                                                delegatedListener.onResponse(searchResponse);
                                            }));
                        },
                        listener::onFailure));
    }

    private void doIndexFieldMappings(
            List<FieldMappingDoc> fieldMappingDocs, ActionListener<Void> listener) {
        if (fieldMappingDocs.isEmpty()) {
            listener.onResponse(null);
        }
        this.getAllFieldMappings(
                ActionListener.wrap(
                        existingFieldMappings -> {
                            List<FieldMappingDoc> mergedFieldMappings = new ArrayList<>();
                            // Disabled pre-packaged log types loading for production builds, enabled only on test
                            // environments.
                            // Issue: https://github.com/wazuh/internal-devel-requests/issues/3587
                            if (this.isLoadBuiltinLogTypesEnabled()) {
                                mergedFieldMappings =
                                        this.mergeFieldMappings(existingFieldMappings, fieldMappingDocs);
                            }
                            BulkRequest bulkRequest = new BulkRequest();
                            bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                            mergedFieldMappings.stream()
                                    .filter(FieldMappingDoc::isDirty)
                                    .forEach(
                                            fieldMappingDoc -> {
                                                IndexRequest indexRequest = new IndexRequest(LOG_TYPE_INDEX);
                                                try {
                                                    indexRequest.id(
                                                            fieldMappingDoc.getId() == null
                                                                    ? this.generateFieldMappingDocId(fieldMappingDoc)
                                                                    : fieldMappingDoc.getId());
                                                    indexRequest.source(
                                                            fieldMappingDoc.toXContent(XContentFactory.jsonBuilder(), null));
                                                    indexRequest.opType(DocWriteRequest.OpType.INDEX);
                                                    bulkRequest.add(indexRequest);
                                                } catch (IOException ex) {
                                                    logger.error("Failed converting FieldMappingDoc to XContent!", ex);
                                                }
                                            });
                            // Index all fieldMapping docs
                            logger.info("Indexing [{}] fieldMappingDocs", bulkRequest.numberOfActions());

                            // Disabled pre-packaged log types loading for production builds, enabled only on test
                            // environments.
                            // Issue: https://github.com/wazuh/internal-devel-requests/issues/3587
                            if (this.isLoadBuiltinLogTypesEnabled()) {
                                this.client.bulk(
                                        bulkRequest,
                                        ActionListener.delegateFailure(
                                                listener,
                                                (l, r) -> {
                                                    if (r.hasFailures()) {
                                                        logger.error(
                                                                "FieldMappingDoc Bulk Index had failures:\n {}",
                                                                r.buildFailureMessage());
                                                        listener.onFailure(new IllegalStateException(r.buildFailureMessage()));
                                                    } else {
                                                        logger.info(
                                                                "Loaded ["
                                                                        + r.getItems().length
                                                                        + "] field mapping docs successfully!");
                                                        listener.onResponse(null);
                                                    }
                                                }));
                            } else {
                                listener.onResponse(null);
                            }
                        },
                        listener::onFailure));
    }

    /**
     * Checks if the 'default_rules.enabled' environment variable is set.
     *
     * @return the value of 'default_rules.enabled'. Returns false if not set.
     */
    private boolean isLoadBuiltinLogTypesEnabled() {
        String isEnabled = System.getProperty("default_rules.enabled");
        return isEnabled != null && isEnabled.equals("true");
    }

    private void doIndexLogTypeMetadata(ActionListener<Void> listener) {
        BoolQueryBuilder queryBuilder =
                QueryBuilders.boolQuery().must(QueryBuilders.existsQuery("space"));
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(queryBuilder);
        searchSourceBuilder.fetchSource(false);
        searchSourceBuilder.size(0);
        searchSourceBuilder.trackTotalHits(true);
        SearchRequest searchRequest = new SearchRequest();
        searchRequest.indices(LogTypeService.LOG_TYPE_INDEX);
        searchRequest.source(searchSourceBuilder);

        this.client.search(
                searchRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (response.isTimedOut()) {
                            listener.onFailure(
                                    new OpenSearchStatusException(
                                            "Search request timed out", RestStatus.REQUEST_TIMEOUT));
                        }
                        if (response.getHits().getHits().length > 0) {
                            listener.onResponse(null);
                        } else {
                            try {
                                List<CustomLogType> customLogTypes = new ArrayList<>();
                                // Disabled pre-packaged log types loading for production builds, enabled only on
                                // test environments.
                                // Issue: https://github.com/wazuh/internal-devel-requests/issues/3587
                                if (LogTypeService.this.isLoadBuiltinLogTypesEnabled()) {
                                    customLogTypes =
                                            LogTypeService.this.builtinLogTypeLoader.loadBuiltinLogTypesMetadata();
                                }
                                BulkRequest bulkRequest = new BulkRequest();

                                for (CustomLogType customLogType : customLogTypes) {
                                    IndexRequest indexRequest =
                                            new IndexRequest(LOG_TYPE_INDEX).id(customLogType.getName());
                                    indexRequest.source(
                                            customLogType.toXContent(XContentFactory.jsonBuilder(), null));
                                    indexRequest.opType(DocWriteRequest.OpType.INDEX);
                                    bulkRequest.add(indexRequest);
                                }

                                if (bulkRequest.numberOfActions() > 0) {
                                    bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                                    logger.info("Indexing [{}] customLogTypes", bulkRequest.numberOfActions());
                                    LogTypeService.this.client.bulk(
                                            bulkRequest,
                                            ActionListener.delegateFailure(
                                                    listener,
                                                    (l, r) -> {
                                                        if (r.hasFailures()) {
                                                            logger.error(
                                                                    "Custom LogType Bulk Index had failures:\n {}",
                                                                    r.buildFailureMessage());
                                                            listener.onFailure(
                                                                    new IllegalStateException(r.buildFailureMessage()));
                                                        } else {
                                                            logger.info(
                                                                    "Loaded [{}] customLogType docs successfully!",
                                                                    r.getItems().length);
                                                            listener.onResponse(null);
                                                        }
                                                    }));
                                } else {
                                    listener.onResponse(null);
                                }
                            } catch (URISyntaxException | IOException e) {
                                listener.onFailure(e);
                            }
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
    }

    private String generateFieldMappingDocId(FieldMappingDoc fieldMappingDoc) {
        String generatedId = fieldMappingDoc.getRawField() + "|";
        if (fieldMappingDoc.getSchemaFields().containsKey(this.defaultSchemaField)) {
            generatedId = generatedId + fieldMappingDoc.getSchemaFields().get(this.defaultSchemaField);
        }
        return generatedId;
    }

    public void indexFieldMappings(
            List<FieldMappingDoc> fieldMappingDocs, ActionListener<Void> listener) {
        this.ensureConfigIndexIsInitialized(
                ActionListener.wrap(
                        e -> {
                            this.doIndexFieldMappings(fieldMappingDocs, listener);
                        },
                        listener::onFailure));
    }

    /**
     * Indexes field mappings unconditionally (bypasses the enabledPrepackaged check). This is used by
     * Wazuh transport actions that need to index field mappings regardless of the
     * default_rules.enabled setting.
     */
    public void indexFieldMappingsForWazuh(
            List<FieldMappingDoc> fieldMappingDocs, ActionListener<Void> listener) {
        this.ensureConfigIndexIsInitialized(
                ActionListener.wrap(
                        e -> this.doIndexFieldMappingsUnconditionally(fieldMappingDocs, listener),
                        listener::onFailure));
    }

    private void doIndexFieldMappingsUnconditionally(
            List<FieldMappingDoc> fieldMappingDocs, ActionListener<Void> listener) {
        if (fieldMappingDocs.isEmpty()) {
            listener.onResponse(null);
            return;
        }

        this.getAllFieldMappings(
                ActionListener.wrap(
                        existingFieldMappings -> {
                            // Always merge field mappings
                            List<FieldMappingDoc> mergedFieldMappings =
                                    this.mergeFieldMappings(existingFieldMappings, fieldMappingDocs);

                            BulkRequest bulkRequest = new BulkRequest();
                            mergedFieldMappings.stream()
                                    .filter(FieldMappingDoc::isDirty)
                                    .forEach(
                                            fieldMappingDoc -> {
                                                IndexRequest indexRequest = new IndexRequest(LOG_TYPE_INDEX);
                                                try {
                                                    indexRequest.id(
                                                            fieldMappingDoc.getId() == null
                                                                    ? this.generateFieldMappingDocId(fieldMappingDoc)
                                                                    : fieldMappingDoc.getId());
                                                    indexRequest.source(
                                                            fieldMappingDoc.toXContent(XContentFactory.jsonBuilder(), null));
                                                    indexRequest.opType(DocWriteRequest.OpType.INDEX);
                                                    bulkRequest.add(indexRequest);
                                                    bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                                                } catch (IOException ex) {
                                                    logger.error("Failed converting FieldMappingDoc to XContent!", ex);
                                                }
                                            });

                            logger.info("Indexing [{}] fieldMappingDocs (Wazuh)", bulkRequest.numberOfActions());

                            if (bulkRequest.numberOfActions() == 0) {
                                listener.onResponse(null);
                                return;
                            }

                            // Always execute the bulk request
                            this.client.bulk(
                                    bulkRequest,
                                    ActionListener.delegateFailure(
                                            listener,
                                            (l, r) -> {
                                                if (r.hasFailures()) {
                                                    logger.error(
                                                            "FieldMappingDoc Bulk Index had failures: ", r.buildFailureMessage());
                                                    listener.onFailure(new IllegalStateException(r.buildFailureMessage()));
                                                } else {
                                                    logger.info(
                                                            "Loaded ["
                                                                    + r.getItems().length
                                                                    + "] field mapping docs successfully!");
                                                    listener.onResponse(null);
                                                }
                                            }));
                        },
                        listener::onFailure));
    }

    private List<FieldMappingDoc> mergeFieldMappings(
            List<FieldMappingDoc> existingFieldMappings, List<FieldMappingDoc> fieldMappingDocs) {
        // Insert new fieldMappings
        List<FieldMappingDoc> newFieldMappings = new ArrayList<>();
        fieldMappingDocs.forEach(
                newFieldMapping -> {
                    Optional<FieldMappingDoc> foundFieldMappingDoc = Optional.empty();
                    for (FieldMappingDoc existingFieldMapping : existingFieldMappings) {
                        if (existingFieldMapping.getRawField().equals(newFieldMapping.getRawField())) {
                            if ((existingFieldMapping.get(this.defaultSchemaField) != null
                                            && newFieldMapping.get(this.defaultSchemaField) != null
                                            && existingFieldMapping
                                                    .get(this.defaultSchemaField)
                                                    .equals(newFieldMapping.get(this.defaultSchemaField)))
                                    || (existingFieldMapping.get(this.defaultSchemaField) == null
                                            && newFieldMapping.get(this.defaultSchemaField) == null)) {
                                foundFieldMappingDoc = Optional.of(existingFieldMapping);
                            }
                            // Grabs the right side of the ID with "|" as the delimiter if present representing
                            // the ecs field from predefined mappings
                            // Additional check to see if raw field path + log type combination is already in
                            // existingFieldMappings so a new one is not indexed
                        } else {
                            String id = existingFieldMapping.getId();
                            int indexOfPipe = id.indexOf("|");
                            if (indexOfPipe != -1) {
                                String ecsIdField = id.substring(indexOfPipe + 1);
                                if (ecsIdField.equals(newFieldMapping.getRawField())
                                        && existingFieldMapping
                                                .getLogTypes()
                                                .containsAll(newFieldMapping.getLogTypes())) {
                                    foundFieldMappingDoc = Optional.of(existingFieldMapping);
                                }
                            }
                        }
                    }
                    if (foundFieldMappingDoc.isEmpty()) {
                        newFieldMapping.setIsDirty(true);
                        newFieldMappings.add(newFieldMapping);
                    } else {
                        // Merge new with existing by merging schema field mappings and log type arrays
                        foundFieldMappingDoc.get().getSchemaFields().putAll(newFieldMapping.getSchemaFields());
                        foundFieldMappingDoc.get().getLogTypes().addAll(newFieldMapping.getLogTypes());
                        foundFieldMappingDoc.get().setIsDirty(true);
                    }
                });
        existingFieldMappings.addAll(newFieldMappings);
        return existingFieldMappings;
    }

    public void getAllFieldMappings(ActionListener<List<FieldMappingDoc>> listener) {
        SearchRequest searchRequest = new SearchRequest(LOG_TYPE_INDEX);
        searchRequest.source(
                new SearchSourceBuilder()
                        .query(QueryBuilders.boolQuery().mustNot(QueryBuilders.existsQuery("space")))
                        .size(10000));
        searchRequest.preference(Preference.PRIMARY_FIRST.type());
        this.client.search(
                searchRequest,
                ActionListener.delegateFailure(
                        listener,
                        (delegatedListener, searchResponse) -> {
                            List<FieldMappingDoc> fieldMappingDocs = new ArrayList<>();
                            for (SearchHit hit : searchResponse.getHits().getHits()) {
                                try {
                                    fieldMappingDocs.add(FieldMappingDoc.parse(hit, this.xContentRegistry));
                                } catch (IOException e) {
                                    logger.error("Failed parsing FieldMapping document", e);
                                    delegatedListener.onFailure(e);
                                    return;
                                }
                            }
                            delegatedListener.onResponse(fieldMappingDocs);
                        }));
    }

    public void getFieldMappingsByLogType(
            String logType, ActionListener<List<FieldMappingDoc>> listener) {
        this.ensureConfigIndexIsInitialized(
                ActionListener.wrap(() -> this.getFieldMappingsByLogTypes(List.of(logType), listener)));
    }

    public void getFieldMappingsByLogTypes(
            List<String> logTypes, ActionListener<List<FieldMappingDoc>> listener) {
        SearchRequest searchRequest = new SearchRequest(LOG_TYPE_INDEX);
        searchRequest.source(
                new SearchSourceBuilder()
                        .query(QueryBuilders.termsQuery(LOG_TYPES, logTypes.toArray(new String[0])))
                        .size(10000));
        searchRequest.preference(Preference.PRIMARY_FIRST.type());
        this.client.search(
                searchRequest,
                ActionListener.delegateFailure(
                        listener,
                        (delegatedListener, searchResponse) -> {
                            List<FieldMappingDoc> fieldMappingDocs = new ArrayList<>();
                            for (SearchHit hit : searchResponse.getHits().getHits()) {
                                try {
                                    fieldMappingDocs.add(FieldMappingDoc.parse(hit, this.xContentRegistry));
                                } catch (IOException e) {
                                    logger.error("Failed parsing FieldMapping document", e);
                                    delegatedListener.onFailure(e);
                                    return;
                                }
                            }
                            delegatedListener.onResponse(fieldMappingDocs);
                        }));
    }

    /**
     * if isConfigIndexInitialized is false does following: 1. Creates log type config index with
     * proper mappings/settings 2. Loads builtin log types into index 3. sets isConfigIndexInitialized
     * to true
     */
    public void ensureConfigIndexIsInitialized(ActionListener<Void> listener) {

        ClusterState state = this.clusterService.state();

        if (!state.routingTable().hasIndex(LOG_TYPE_INDEX)) {
            isConfigIndexInitialized = false;
            Settings indexSettings =
                    Settings.builder()
                            .put("index.hidden", true)
                            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                            .put(
                                    "index.auto_expand_replicas",
                                    minSystemIndexReplicas + "-" + maxSystemIndexReplicas)
                            .build();

            CreateIndexRequest createIndexRequest = new CreateIndexRequest();
            createIndexRequest.settings(this.logTypeIndexSettings());
            createIndexRequest.index(LOG_TYPE_INDEX);
            createIndexRequest.mapping(this.logTypeIndexMapping());
            createIndexRequest.settings(indexSettings);
            createIndexRequest.cause("auto(sap-logtype api)");
            this.client
                    .admin()
                    .indices()
                    .create(
                            createIndexRequest,
                            new ActionListener<>() {
                                @Override
                                public void onResponse(CreateIndexResponse result) {
                                    LogTypeService.this.waitForIndexShardsAndLoad(listener);
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    isConfigIndexInitialized = false;
                                    if (ExceptionsHelper.unwrapCause(e) instanceof ResourceAlreadyExistsException) {
                                        LogTypeService.this.waitForIndexShardsAndLoad(listener);
                                    } else {
                                        logger.error("Failed creating {}: {}", LOG_TYPE_INDEX, e.getMessage());
                                        listener.onFailure(e);
                                    }
                                }
                            });
        } else {
            IndexMetadata metadata = state.getMetadata().index(LOG_TYPE_INDEX);
            if (this.getConfigIndexMappingVersion(metadata) < this.logTypeMappingVersion) {
                // The index already exists but doesn't have our mapping
                this.client
                        .admin()
                        .indices()
                        .preparePutMapping(LOG_TYPE_INDEX)
                        .setSource(this.logTypeIndexMapping(), XContentType.JSON)
                        .execute(
                                ActionListener.delegateFailure(
                                        listener,
                                        (l, r) -> {
                                            this.loadBuiltinLogTypes(
                                                    ActionListener.delegateFailure(
                                                            listener,
                                                            (delegatedListener, unused) -> {
                                                                isConfigIndexInitialized = true;
                                                                this.doIndexLogTypeMetadata(listener);
                                                            }));
                                        }));
            } else {
                if (isConfigIndexInitialized) {
                    this.doIndexLogTypeMetadata(listener);
                    return;
                }
                this.loadBuiltinLogTypes(
                        ActionListener.delegateFailure(
                                listener,
                                (delegatedListener, unused) -> {
                                    isConfigIndexInitialized = true;
                                    this.doIndexLogTypeMetadata(listener);
                                }));
            }
        }
    }

    /**
     * Waits for at least one active shard on LOG_TYPE_INDEX before loading built-in log types. This
     * prevents "all shards failed" errors that occur when index creation is acknowledged but the
     * primary shard is not yet assigned/started.
     */
    private void waitForIndexShardsAndLoad(ActionListener<Void> listener) {
        ClusterHealthRequest healthRequest =
                new ClusterHealthRequest(LOG_TYPE_INDEX).waitForActiveShards(ActiveShardCount.ONE);
        this.client
                .admin()
                .cluster()
                .health(
                        healthRequest,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(ClusterHealthResponse response) {
                                if (response.getStatus() == ClusterHealthStatus.RED) {
                                    logger.warn("{} health is RED after waiting for shards", LOG_TYPE_INDEX);
                                }
                                LogTypeService.this.loadBuiltinLogTypes(
                                        ActionListener.delegateFailure(
                                                listener,
                                                (delegatedListener, unused) -> {
                                                    isConfigIndexInitialized = true;
                                                    LogTypeService.this.doIndexLogTypeMetadata(listener);
                                                }));
                            }

                            @Override
                            public void onFailure(Exception e) {
                                isConfigIndexInitialized = false;
                                logger.error(
                                        "Failed waiting for {} shards to become active: {}",
                                        LOG_TYPE_INDEX,
                                        e.getMessage());
                                listener.onFailure(e);
                            }
                        });
    }

    public void loadBuiltinLogTypes(ActionListener<Void> listener) {
        logger.info("Loading builtin types!");
        List<LogType> logTypes = new ArrayList<>();
        // Disabled pre-packaged log types loading for production builds, enabled only on test
        // environments.
        // Issue: https://github.com/wazuh/internal-devel-requests/issues/3587
        if (this.isLoadBuiltinLogTypesEnabled()) {
            logger.info("default_rules.enabled is true, loading pre-packaged log types from disk.");
            logTypes = this.builtinLogTypeLoader.getAllLogTypes();
            if (logTypes == null || logTypes.isEmpty()) {
                logger.error("Failed loading builtin log types from disk!");
                listener.onFailure(
                        SecurityAnalyticsException.wrap(
                                new IllegalStateException("Failed loading builtin log types from disk!")));
                return;
            }
        }
        List<FieldMappingDoc> fieldMappingDocs = this.createFieldMappingDocs(logTypes);
        logger.info(
                "Indexing [{}] fieldMappingDocs from logTypes: {}",
                fieldMappingDocs.size(),
                logTypes.size());
        this.doIndexFieldMappings(fieldMappingDocs, listener);
    }

    /** Loops through all builtin LogTypes and creates collection of FieldMappingDocs */
    private List<FieldMappingDoc> createFieldMappingDocs(List<LogType> logTypes) {
        Map<String, FieldMappingDoc> fieldMappingMap = new HashMap<>();

        logTypes.stream()
                .filter(e -> e.getMappings() != null)
                .forEach(
                        logType ->
                                logType
                                        .getMappings()
                                        .forEach(
                                                mapping -> {
                                                    // key is rawField + defaultSchemaField(ecs)
                                                    String key = mapping.getRawField() + "|" + mapping.getEcs();
                                                    FieldMappingDoc existingDoc = fieldMappingMap.get(key);
                                                    if (existingDoc == null) {
                                                        // create new doc
                                                        Map<String, String> schemaFields = new HashMap<>();
                                                        if (mapping.getEcs() != null) {
                                                            schemaFields.put("ecs", mapping.getEcs());
                                                        }
                                                        if (mapping.getOcsf() != null) {
                                                            schemaFields.put("ocsf", mapping.getOcsf());
                                                        }
                                                        if (mapping.getOcsf11() != null) {
                                                            schemaFields.put("ocsf11", mapping.getOcsf11());
                                                        }
                                                        fieldMappingMap.put(
                                                                key,
                                                                new FieldMappingDoc(
                                                                        mapping.getRawField(),
                                                                        schemaFields,
                                                                        Sets.newHashSet(logType.getName())));
                                                    } else {
                                                        // merge with existing doc
                                                        existingDoc.getSchemaFields().put("ocsf", mapping.getOcsf());
                                                        existingDoc.getSchemaFields().put("ocsf11", mapping.getOcsf11());
                                                        existingDoc.getLogTypes().add(logType.getName());
                                                    }
                                                }));
        return new ArrayList<>(fieldMappingMap.values());
    }

    public String logTypeIndexMapping() {
        try (InputStream is =
                this.getClass().getClassLoader().getResourceAsStream(LOG_TYPE_INDEX_MAPPING_FILE)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.copy(is, out);
            return out.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error(
                    () ->
                            new ParameterizedMessage(
                                    "failed to load log-type-index mapping file [{}]", LOG_TYPE_INDEX_MAPPING_FILE),
                    e);
            throw new IllegalStateException(
                    "failed to load log-type-index mapping file [" + LOG_TYPE_INDEX_MAPPING_FILE + "]", e);
        }
    }

    private Settings logTypeIndexSettings() {
        return Settings.builder().put(IndexMetadata.INDEX_HIDDEN_SETTING.getKey(), "true").build();
    }

    private int getConfigIndexMappingVersion(IndexMetadata metadata) {
        MappingMetadata mappingMetadata = metadata.mapping();
        if (mappingMetadata == null) {
            return 0;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) mappingMetadata.sourceAsMap().get("_meta");
        if (meta == null || !meta.containsKey(LOG_TYPE_MAPPING_VERSION_META_FIELD)) {
            return 1; // The mapping was created before meta field was introduced
        }
        return (int) meta.get(LOG_TYPE_MAPPING_VERSION_META_FIELD);
    }

    public List<LogType> getAllBuiltinLogTypes() {
        return this.builtinLogTypeLoader.getAllLogTypes();
    }

    public void getRuleFieldMappings(ActionListener<Map<String, Map<String, String>>> listener) {
        this.ensureConfigIndexIsInitialized(
                ActionListener.wrap(
                        () ->
                                this.getAllFieldMappings(
                                        ActionListener.delegateFailure(
                                                listener,
                                                (delegatedListener, fieldMappingDocs) -> {
                                                    Map<String, Map<String, String>> mappings = new HashMap<>();
                                                    for (FieldMappingDoc fieldMappingDoc : fieldMappingDocs) {
                                                        Set<String> logTypes = fieldMappingDoc.getLogTypes();
                                                        if (logTypes != null) {
                                                            for (String logType : logTypes) {
                                                                Map<String, String> mappingsByLogTypes =
                                                                        mappings.containsKey(logType)
                                                                                ? mappings.get(logType)
                                                                                : new HashMap<>();
                                                                mappingsByLogTypes.put(
                                                                        fieldMappingDoc.getRawField(),
                                                                        fieldMappingDoc.getSchemaFields().get(this.defaultSchemaField));
                                                                mappings.put(logType, mappingsByLogTypes);
                                                            }
                                                        }
                                                    }
                                                    delegatedListener.onResponse(mappings);
                                                }))));
    }

    /**
     * Returns sigmaRule rawField to default_schema_field(ECS) mapping
     *
     * @param logType Log type Returns Map of rawField to ecs field via listener
     */
    public void getRuleFieldMappings(String logType, ActionListener<Map<String, String>> listener) {

        if (this.builtinLogTypeLoader.logTypeExists(logType)) {
            LogType lt = this.builtinLogTypeLoader.getLogTypeByName(logType);
            if (lt.getMappings() == null) {
                listener.onResponse(Map.of());
            } else {
                listener.onResponse(
                        lt.getMappings().stream()
                                .collect(Collectors.toMap(LogType.Mapping::getRawField, LogType.Mapping::getEcs)));
            }
            return;
        }

        this.getFieldMappingsByLogType(
                logType,
                ActionListener.delegateFailure(
                        listener,
                        (delegatedListener, fieldMappingDocs) -> {
                            Map<String, String> ruleFieldMappings = new HashMap<>(fieldMappingDocs.size());
                            fieldMappingDocs.forEach(
                                    e -> {
                                        ruleFieldMappings.put(
                                                e.getRawField(), e.getSchemaFields().get(this.defaultSchemaField));
                                    });
                            delegatedListener.onResponse(ruleFieldMappings);
                        }));
    }

    public List<LogType.IocFields> getIocFieldsList(String logType) {
        LogType logTypeByName = this.builtinLogTypeLoader.getLogTypeByName(logType);
        if (logTypeByName == null) return Collections.emptyList();
        return logTypeByName.getIocFieldsList();
    }

    public void getRuleFieldMappingsAllSchemas(
            String logType, ActionListener<List<LogType.Mapping>> listener) {

        if (this.builtinLogTypeLoader.logTypeExists(logType)) {
            LogType lt = this.builtinLogTypeLoader.getLogTypeByName(logType);
            if (lt.getMappings() == null) {
                listener.onResponse(List.of());
            } else {
                listener.onResponse(lt.getMappings());
            }
            return;
        }

        this.getFieldMappingsByLogType(
                logType,
                ActionListener.delegateFailure(
                        listener,
                        (delegatedListener, fieldMappingDocs) -> {
                            List<LogType.Mapping> ruleFieldMappings = new ArrayList<>();
                            fieldMappingDocs.forEach(
                                    e -> {
                                        ruleFieldMappings.add(
                                                new LogType.Mapping(
                                                        e.getRawField(),
                                                        e.getSchemaFields().get("ecs"),
                                                        e.getSchemaFields().get("ocsf"),
                                                        e.getSchemaFields().get("ocsf11")));
                                    });
                            delegatedListener.onResponse(ruleFieldMappings);
                        }));
    }

    /** Provides required fields for a log type in order for all rules to work */
    public void getRequiredFields(String logType, ActionListener<List<LogType.Mapping>> listener) {

        this.getFieldMappingsByLogType(
                logType,
                ActionListener.delegateFailure(
                        listener,
                        (delegatedListener, fieldMappingDocs) -> {
                            List<LogType.Mapping> requiredFields = new ArrayList<>();
                            fieldMappingDocs.forEach(
                                    e -> {
                                        LogType.Mapping requiredField =
                                                new LogType.Mapping(
                                                        e.getRawField(),
                                                        e.getSchemaFields().get(this.defaultSchemaField),
                                                        e.getSchemaFields().get("ocsf"),
                                                        e.getSchemaFields().get("ocsf11"));
                                        requiredFields.add(requiredField);
                                    });
                            delegatedListener.onResponse(requiredFields);
                        }));
    }

    /** Provides required fields for all log types in a form of map */
    public void getRequiredFieldsForAllLogTypes(ActionListener<Map<String, Set<String>>> listener) {
        this.ensureConfigIndexIsInitialized(
                ActionListener.wrap(
                        () ->
                                this.getAllFieldMappings(
                                        ActionListener.delegateFailure(
                                                listener,
                                                (delegatedListener, fieldMappingDocs) -> {
                                                    Map<String, Set<String>> requiredFieldsMap = new HashMap<>();
                                                    fieldMappingDocs.forEach(
                                                            e -> {
                                                                // Init sets if first time seeing this logType
                                                                e.getLogTypes()
                                                                        .forEach(
                                                                                logType -> {
                                                                                    if (!requiredFieldsMap.containsKey(logType)) {
                                                                                        requiredFieldsMap.put(logType, new HashSet<>());
                                                                                    }
                                                                                });
                                                                String requiredField =
                                                                        e.getSchemaFields().get(this.defaultSchemaField);
                                                                if (requiredField == null) {
                                                                    requiredField = e.getRawField(); // Always fallback to rawField if
                                                                    // defaultSchema one is missing
                                                                }
                                                                final String _requiredField = requiredField;
                                                                e.getLogTypes()
                                                                        .forEach(
                                                                                logType -> {
                                                                                    requiredFieldsMap.get(logType).add(_requiredField);
                                                                                });
                                                            });
                                                    delegatedListener.onResponse(requiredFieldsMap);
                                                }))));
    }

    /**
     * Returns sigmaRule rawField to default_schema_field(ECS) mapping, but works with builtin types
     * only!
     *
     * @param builtinLogType Built-in (prepackaged) Log type
     * @return Map of rawField to ecs field via listener
     */
    public Map<String, String> getRuleFieldMappingsForBuiltinLogType(String builtinLogType) {

        if (!this.builtinLogTypeLoader.logTypeExists(builtinLogType)) {
            return null;
        }

        LogType lt = this.builtinLogTypeLoader.getLogTypeByName(builtinLogType);
        if (lt.getMappings() == null) {
            return Map.of();
        } else {
            return lt.getMappings().stream()
                    .collect(Collectors.toMap(LogType.Mapping::getRawField, LogType.Mapping::getEcs));
        }
    }

    public String getDefaultSchemaField() {
        return this.defaultSchemaField;
    }

    public void setLogTypeMappingVersion() {
        Map<String, Object> logTypeConfigAsMap =
                XContentHelper.convertToMap(JsonXContent.jsonXContent, this.logTypeIndexMapping(), false);
        this.logTypeMappingVersion =
                (int) ((Map) logTypeConfigAsMap.get("_meta")).get("schema_version");
    }
}
