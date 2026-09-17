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

import org.opensearch.OpenSearchException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.support.ActiveShardCount;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.ClusterAdminClient;
import org.junit.Assert;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import org.mockito.ArgumentCaptor;

import static org.opensearch.securityanalytics.TestHelpers.parser;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IndexUtilsTests extends OpenSearchTestCase {

    public void testGetSchemaVersion() throws IOException {
        String message = "{\"user\":{ \"name\":\"test\"},\"_meta\":{\"schema_version\": 1}}";

        int schemaVersion = IndexUtils.getSchemaVersion(message);
        Assert.assertEquals(1, schemaVersion);
    }

    public void testGetSchemaVersionWithoutMeta() throws IOException {
        String message = "{\"user\":{ \"name\":\"test\"}}";

        int schemaVersion = IndexUtils.getSchemaVersion(message);
        Assert.assertEquals(0, schemaVersion);
    }

    public void testGetSchemaVersionWithoutSchemaVersion() throws IOException {
        String message = "{\"user\":{ \"name\":\"test\"},\"_meta\":{\"test\": 1}}";

        int schemaVersion = IndexUtils.getSchemaVersion(message);
        Assert.assertEquals(0, schemaVersion);
    }

    public void testGetSchemaVersionWithNegativeSchemaVersion() {
        String message = "{\"user\":{ \"name\":\"test\"},\"_meta\":{\"schema_version\": -1}}";

        assertThrows(
                IllegalArgumentException.class,
                () -> {
                    IndexUtils.getSchemaVersion(message);
                });
    }

    public void testGetSchemaVersionWithWrongSchemaVersion() {
        String message = "{\"user\":{ \"name\":\"test\"},\"_meta\":{\"schema_version\": \"wrong\"}}";

        assertThrows(
                IllegalArgumentException.class,
                () -> {
                    IndexUtils.getSchemaVersion(message);
                });
    }

    public void testShouldUpdateIndexWithoutOriginalVersion() throws IOException {
        String indexContent =
                "{\"testIndex\":{\"settings\":{\"index\":{\"creation_date\":\"1558407515699\","
                        + "\"number_of_shards\":\"1\",\"number_of_replicas\":\"1\",\"uuid\":\"t-VBBW6aR6KpJ3XP5iISOA\","
                        + "\"version\":{\"created\":\"136217927\"},\"provided_name\":\"data_test\"}},\"mapping_version\":123,"
                        + "\"settings_version\":123,\"aliases_version\":1,\"mappings\":{\"_doc\":{\"properties\":{\"name\":{\"type\":\"keyword\"}}}}}}";

        String newMapping =
                "{\"_meta\":{\"schema_version\":10},\"properties\":{\"name\":{\"type\":\"keyword\"}}}";
        IndexMetadata index = IndexMetadata.fromXContent(parser(indexContent));
        boolean shouldUpdateIndex = IndexUtils.shouldUpdateIndex(index, newMapping);

        Assert.assertTrue(shouldUpdateIndex);
    }

    public void testShouldUpdateIndexWithLaggedVersion() throws IOException {
        String indexContent =
                "{\"testIndex\":{\"settings\":{\"index\":{\"creation_date\":\"1558407515699\","
                        + "\"number_of_shards\":\"1\",\"number_of_replicas\":\"1\",\"uuid\":\"t-VBBW6aR6KpJ3XP5iISOA\","
                        + "\"version\":{\"created\":\"136217927\"},\"provided_name\":\"data_test\"}},\"mapping_version\":123,"
                        + "\"settings_version\":123,\"aliases_version\":1,\"mappings\":{\"_doc\":{\"_meta\":{\"schema_version\":1},\"properties\":"
                        + "{\"name\":{\"type\":\"keyword\"}}}}}}";

        String newMapping =
                "{\"_meta\":{\"schema_version\":10},\"properties\":{\"name\":{\"type\":\"keyword\"}}}";
        IndexMetadata index = IndexMetadata.fromXContent(parser(indexContent));
        boolean shouldUpdateIndex = IndexUtils.shouldUpdateIndex(index, newMapping);

        Assert.assertTrue(shouldUpdateIndex);
    }

    public void testShouldUpdateIndexWithSameVersion() throws IOException {
        String indexContent =
                "{\"testIndex\":{\"settings\":{\"index\":{\"creation_date\":\"1558407515699\","
                        + "\"number_of_shards\":\"1\",\"number_of_replicas\":\"1\",\"uuid\":\"t-VBBW6aR6KpJ3XP5iISOA\","
                        + "\"version\":{\"created\":\"136217927\"},\"provided_name\":\"data_test\"}},\"mapping_version\":\"1\","
                        + "\"settings_version\":\"1\",\"aliases_version\":\"1\",\"mappings\":"
                        + "{\"_doc\":{\"_meta\":{\"schema_version\":1},\"properties\":{\"name\":{\"type\":\"keyword\"}}}}}}";

        String newMapping =
                "{\"_meta\":{\"schema_version\":10},\"properties\":{\"name\":{\"type\":\"keyword\"}}}";
        IndexMetadata index = IndexMetadata.fromXContent(parser(indexContent));
        boolean shouldUpdateIndex = IndexUtils.shouldUpdateIndex(index, newMapping);

        Assert.assertTrue(shouldUpdateIndex);
    }

    @SuppressWarnings("unchecked")
    private static ClusterAdminClient stubClusterHealth(
            Client client, ClusterHealthResponse response, Exception failure) {
        AdminClient adminClient = mock(AdminClient.class);
        ClusterAdminClient clusterAdminClient = mock(ClusterAdminClient.class);
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.cluster()).thenReturn(clusterAdminClient);
        doAnswer(
                        invocation -> {
                            ActionListener<ClusterHealthResponse> listener = invocation.getArgument(1);
                            if (failure == null) {
                                listener.onResponse(response);
                            } else {
                                listener.onFailure(failure);
                            }
                            return null;
                        })
                .when(clusterAdminClient)
                .health(any(ClusterHealthRequest.class), any(ActionListener.class));
        return clusterAdminClient;
    }

    @SuppressWarnings("unchecked")
    public void testWaitForActiveShard_asksForOneActiveShardOnTheGivenIndex() {
        Client client = mock(Client.class);
        ClusterHealthResponse response = mock(ClusterHealthResponse.class);
        when(response.getStatus()).thenReturn(ClusterHealthStatus.GREEN);
        ClusterAdminClient clusterAdminClient = stubClusterHealth(client, response, null);

        AtomicReference<Boolean> completed = new AtomicReference<>(false);
        IndexUtils.waitForActiveShard(
                client,
                ".test-config",
                ActionListener.wrap(unused -> completed.set(true), e -> Assert.fail(e.getMessage())));

        ArgumentCaptor<ClusterHealthRequest> request =
                ArgumentCaptor.forClass(ClusterHealthRequest.class);
        org.mockito.Mockito.verify(clusterAdminClient)
                .health(request.capture(), any(ActionListener.class));
        Assert.assertArrayEquals(new String[] {".test-config"}, request.getValue().indices());
        Assert.assertEquals(ActiveShardCount.ONE, request.getValue().waitForActiveShards());
        Assert.assertTrue(completed.get());
    }

    public void testWaitForActiveShard_completesOnRedHealth() {
        // RED only means no shard came up within the health timeout. It is worth a warning, but the
        // decision of what to do next belongs to the caller, so the listener still completes.
        Client client = mock(Client.class);
        ClusterHealthResponse response = mock(ClusterHealthResponse.class);
        when(response.getStatus()).thenReturn(ClusterHealthStatus.RED);
        stubClusterHealth(client, response, null);

        AtomicReference<Boolean> completed = new AtomicReference<>(false);
        IndexUtils.waitForActiveShard(
                client,
                ".test-config",
                ActionListener.wrap(unused -> completed.set(true), e -> Assert.fail(e.getMessage())));

        Assert.assertTrue(completed.get());
    }

    public void testWaitForActiveShard_propagatesHealthFailure() {
        Client client = mock(Client.class);
        stubClusterHealth(client, null, new OpenSearchException("health request failed"));

        AtomicReference<Exception> failure = new AtomicReference<>();
        IndexUtils.waitForActiveShard(
                client,
                ".test-config",
                ActionListener.wrap(unused -> Assert.fail("expected a failure"), failure::set));

        Assert.assertNotNull(failure.get());
        Assert.assertEquals("health request failed", failure.get().getMessage());
    }
}
