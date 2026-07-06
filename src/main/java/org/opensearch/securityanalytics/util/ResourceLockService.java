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
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Serializes the resource-creation-limit check-then-act sequence (count existing documents, then
 * create if under the configured max) with a short-lived mutex document per lock ID.
 *
 * <p>The mutex is a document with a caller-supplied ID, created via {@link
 * DocWriteRequest.OpType#CREATE} so only one caller can hold it at a time for that ID -- the same
 * atomic-guard technique used elsewhere in this plugin (see {@link
 * org.opensearch.securityanalytics.enrichment.WazuhEnrichedFindingService}) to insert idempotently.
 * The resource count itself remains a live search against the resource index; the lock only
 * prevents two requests from evaluating that count concurrently with a create.
 */
public class ResourceLockService {

    private static final Logger log = LogManager.getLogger(ResourceLockService.class);

    public static final String LOCKS_INDEX = ".opensearch-sap-resource-locks";
    private static final String MAPPING_PATH = "mappings/resource-locks.json";
    private static final String ACQUIRED_AT_FIELD = "acquired_at";
    private static final int MAX_ACQUIRE_RETRIES = 20;
    private static final long ACQUIRE_RETRY_BACKOFF_MILLIS = 100;
    private static final long STALE_THRESHOLD_MILLIS = 30_000;

    private final Client client;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;

    public ResourceLockService(Client client, ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    private static String lockMappings() throws IOException {
        return new String(
                Objects.requireNonNull(
                                ResourceLockService.class.getClassLoader().getResourceAsStream(MAPPING_PATH))
                        .readAllBytes(),
                Charset.defaultCharset());
    }

    private boolean locksIndexExists() {
        return this.clusterService.state().getRoutingTable().hasIndex(LOCKS_INDEX);
    }

    private void ensureIndexExists(ActionListener<Void> listener) {
        if (this.locksIndexExists()) {
            listener.onResponse(null);
            return;
        }
        Settings indexSettings =
                Settings.builder()
                        .put("index.hidden", true)
                        .put("index.number_of_shards", 1)
                        .put("index.number_of_replicas", 0)
                        .put("index.refresh_interval", "-1")
                        .build();
        CreateIndexRequest request;
        try {
            request = new CreateIndexRequest(LOCKS_INDEX).mapping(lockMappings()).settings(indexSettings);
        } catch (IOException e) {
            listener.onFailure(e);
            return;
        }
        this.client
                .admin()
                .indices()
                .create(
                        request,
                        ActionListener.wrap(
                                response -> listener.onResponse(null),
                                e -> {
                                    if (ExceptionsHelper.unwrapCause(e) instanceof ResourceAlreadyExistsException) {
                                        listener.onResponse(null);
                                    } else {
                                        listener.onFailure(e);
                                    }
                                }));
    }

    /**
     * Acquires the mutex for the given lock ID, blocking the calling continuation (via retries
     * scheduled on the generic thread pool) until it becomes available.
     *
     * @param lockId the lock document ID.
     * @param listener notified with {@code lockId} once acquired, or with a {@link
     *     OpenSearchStatusException} ({@code 429}) if the lock could not be acquired after {@link
     *     #MAX_ACQUIRE_RETRIES} attempts.
     */
    public void acquire(String lockId, ActionListener<String> listener) {
        this.ensureIndexExists(
                ActionListener.wrap(
                        ignored -> this.attemptAcquire(lockId, 1, listener), listener::onFailure));
    }

    private void attemptAcquire(String lockId, int attempt, ActionListener<String> listener) {
        IndexRequest request =
                new IndexRequest(LOCKS_INDEX)
                        .id(lockId)
                        .source(Map.of(ACQUIRED_AT_FIELD, Instant.now().toEpochMilli()))
                        .opType(DocWriteRequest.OpType.CREATE)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        this.client.index(
                request,
                ActionListener.wrap(
                        response -> listener.onResponse(lockId),
                        e -> {
                            if (!(ExceptionsHelper.unwrapCause(e) instanceof VersionConflictEngineException)) {
                                listener.onFailure(e);
                                return;
                            }
                            if (attempt >= MAX_ACQUIRE_RETRIES) {
                                listener.onFailure(
                                        new OpenSearchStatusException(
                                                "Timed out waiting for the resource-creation lock on [" + lockId + "].",
                                                RestStatus.TOO_MANY_REQUESTS));
                                return;
                            }
                            this.stealIfStale(
                                    lockId,
                                    ActionListener.wrap(
                                            stolen -> {
                                                if (stolen) {
                                                    this.attemptAcquire(lockId, attempt + 1, listener);
                                                } else {
                                                    this.threadPool.schedule(
                                                            () -> this.attemptAcquire(lockId, attempt + 1, listener),
                                                            TimeValue.timeValueMillis(ACQUIRE_RETRY_BACKOFF_MILLIS),
                                                            ThreadPool.Names.GENERIC);
                                                }
                                            },
                                            listener::onFailure));
                        }));
    }

    /**
     * Releases a previously acquired lock. Failures are logged and swallowed so a release problem
     * never surfaces as a resource-creation failure; a lock older than {@link
     * #STALE_THRESHOLD_MILLIS} is stolen by the next caller regardless.
     *
     * @param lockId the lock document ID returned by {@link #acquire(String, ActionListener)}.
     */
    public void release(String lockId) {
        DeleteRequest request =
                new DeleteRequest(LOCKS_INDEX, lockId)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        this.client.delete(
                request,
                ActionListener.wrap(
                        response -> {},
                        e ->
                                log.warn(
                                        "Failed to release resource-creation lock [{}]: {}", lockId, e.getMessage())));
    }

    /**
     * Deletes the lock document if it was acquired more than {@link #STALE_THRESHOLD_MILLIS} ago,
     * guarding against a lock orphaned by a crashed node.
     *
     * @param lockId the lock document ID.
     * @param listener notified with {@code true} if the caller should retry immediately (the lock was
     *     stolen, or had already been released), {@code false} otherwise.
     */
    private void stealIfStale(String lockId, ActionListener<Boolean> listener) {
        this.client.get(
                new GetRequest(LOCKS_INDEX, lockId),
                ActionListener.wrap(
                        response -> {
                            if (!response.isExists()) {
                                // Released concurrently between our failed acquire and this check; retry
                                // immediately.
                                listener.onResponse(true);
                                return;
                            }
                            Map<String, Object> source = response.getSourceAsMap();
                            Object acquiredAt = source != null ? source.get(ACQUIRED_AT_FIELD) : null;
                            long acquiredAtMillis =
                                    acquiredAt instanceof Number ? ((Number) acquiredAt).longValue() : 0L;
                            if (Instant.now().toEpochMilli() - acquiredAtMillis <= STALE_THRESHOLD_MILLIS) {
                                listener.onResponse(false);
                                return;
                            }
                            log.warn("Stealing stale resource-creation lock [{}].", lockId);
                            DeleteRequest deleteRequest =
                                    new DeleteRequest(LOCKS_INDEX, lockId)
                                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                            this.client.delete(
                                    deleteRequest,
                                    ActionListener.wrap(
                                            deleteResponse -> listener.onResponse(true), listener::onFailure));
                        },
                        e -> {
                            log.warn(
                                    "Failed to check staleness of resource-creation lock [{}]: {}",
                                    lockId,
                                    e.getMessage());
                            listener.onResponse(false);
                        }));
    }
}
