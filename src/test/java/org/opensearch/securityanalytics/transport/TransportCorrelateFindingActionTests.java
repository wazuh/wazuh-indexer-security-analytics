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

import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.commons.alerting.action.PublishFindingsRequest;
import org.opensearch.commons.alerting.action.SubscribeFindingsResponse;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.correlation.CorrelationRulesCache;
import org.opensearch.securityanalytics.correlation.DetectorLookupCache;
import org.opensearch.securityanalytics.correlation.LogTypeListCache;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.correlation.alert.notifications.NotificationService;
import org.opensearch.securityanalytics.enrichment.WazuhEnrichedFindingService;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.tasks.Task;
import org.opensearch.tasks.TaskManager;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TransportCorrelateFindingActionTests extends OpenSearchTestCase {

    public void testAddLogTypeIfValid_withValidSource_addsLogType() {
        Map<String, CustomLogType> logTypes = new HashMap<>();

        TransportCorrelateFindingAction.addLogTypeIfValid(
                logTypes, validSource("windows", "Windows logs"), "hit-1", "monitor-1", "finding-1");

        assertEquals(1, logTypes.size());
        assertTrue(logTypes.containsKey("windows"));
        assertEquals("Windows logs", logTypes.get("windows").getDescription());
    }

    public void testAddLogTypeIfValid_missingName_skipsSource() {
        Map<String, CustomLogType> logTypes = new HashMap<>();
        Map<String, Object> source = new HashMap<>();
        source.put("description", "Linux logs");
        source.put("space", "default");
        source.put("tags", Map.of("source", "linux"));

        TransportCorrelateFindingAction.addLogTypeIfValid(
                logTypes, source, "hit-missing-name", "monitor-1", "finding-1");

        assertTrue(logTypes.isEmpty());
    }

    public void testAddLogTypeIfValid_mixedSources_keepsOnlyValidEntries() {
        Map<String, CustomLogType> logTypes = new HashMap<>();

        Map<String, Object> missingNameSource = new HashMap<>();
        missingNameSource.put("description", "Missing name");
        missingNameSource.put("space", "default");
        missingNameSource.put("tags", Map.of("source", "broken"));

        Map<String, Object> missingDescriptionSource = new HashMap<>();
        missingDescriptionSource.put("name", "broken");
        missingDescriptionSource.put("space", "default");
        missingDescriptionSource.put("tags", Map.of("source", "broken"));

        TransportCorrelateFindingAction.addLogTypeIfValid(
                logTypes, validSource("apache", "Apache logs"), "hit-valid", "monitor-1", "finding-1");
        TransportCorrelateFindingAction.addLogTypeIfValid(
                logTypes, missingNameSource, "hit-missing-name", "monitor-1", "finding-1");
        TransportCorrelateFindingAction.addLogTypeIfValid(
                logTypes, missingDescriptionSource, "hit-missing-description", "monitor-1", "finding-1");

        assertEquals(1, logTypes.size());
        assertTrue(logTypes.containsKey("apache"));
    }

    private static Map<String, Object> validSource(String name, String description) {
        Map<String, Object> source = new HashMap<>();
        source.put("name", name);
        source.put("description", description);
        source.put("space", "default");
        source.put("category", "web");
        source.put("tags", Map.of("source", "wazuh"));
        return source;
    }

    private static class TestSetup {
        Client client;
        CorrelationIndices correlationIndices;
        DetectorIndices detectorIndices;
        ThreadPool threadPool;
        TransportCorrelateFindingAction transportAction;
    }

    private TestSetup buildTestSetup() {
        TestSetup s = new TestSetup();
        s.client = mock(Client.class);
        s.correlationIndices = mock(CorrelationIndices.class);
        s.detectorIndices = mock(DetectorIndices.class);
        s.threadPool = mock(ThreadPool.class);

        ClusterService clusterService = mock(ClusterService.class);
        ClusterSettings clusterSettings =
                new ClusterSettings(
                        Settings.EMPTY,
                        new HashSet<>(
                                Arrays.asList(
                                        SecurityAnalyticsSettings.INDEX_TIMEOUT,
                                        SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW,
                                        SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS,
                                        SecurityAnalyticsSettings.ENRICHED_FINDINGS_ENABLED,
                                        SecurityAnalyticsSettings.CORRELATION_DETECTOR_CACHE_TTL,
                                        SecurityAnalyticsSettings.CORRELATION_MAX_IN_FLIGHT_FINDINGS,
                                        SecurityAnalyticsSettings.CORRELATION_METADATA_CACHE_TTL)));
        when(clusterService.getClusterSettings()).thenReturn(clusterSettings);
        when(clusterService.state()).thenReturn(ClusterState.builder(new ClusterName("test")).build());
        when(s.detectorIndices.getThreadPool()).thenReturn(s.threadPool);
        when(s.threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));

        ExecutorService executor = mock(ExecutorService.class);
        doAnswer(
                        inv -> {
                            ((Runnable) inv.getArgument(0)).run();
                            return null;
                        })
                .when(executor)
                .execute(any());
        when(s.threadPool.executor(anyString())).thenReturn(executor);

        TransportService transportService = mock(TransportService.class);
        when(transportService.getTaskManager()).thenReturn(mock(TaskManager.class));

        s.transportAction =
                new TransportCorrelateFindingAction(
                        transportService,
                        s.client,
                        mock(NamedXContentRegistry.class),
                        s.detectorIndices,
                        s.correlationIndices,
                        mock(LogTypeService.class),
                        clusterService,
                        Settings.EMPTY,
                        new ActionFilters(Collections.emptySet()),
                        mock(CorrelationAlertService.class),
                        mock(NotificationService.class),
                        mock(WazuhEnrichedFindingService.class),
                        new DetectorLookupCache(TimeValue.ZERO),
                        new LogTypeListCache(TimeValue.ZERO),
                        new CorrelationRulesCache(TimeValue.ZERO));
        return s;
    }

    private TransportCorrelateFindingAction.AsyncCorrelateFindingAction buildAsyncAction(
            TestSetup s, ActionListener<SubscribeFindingsResponse> listener) {
        Finding finding =
                new Finding(
                        "finding-1",
                        List.of("doc-1"),
                        List.of("doc-1"),
                        "monitor-1",
                        "monitor-name",
                        "test-index",
                        Collections.emptyList(),
                        Instant.now(),
                        "high");
        PublishFindingsRequest request = new PublishFindingsRequest("monitor-1", finding);

        return s.transportAction
        .new AsyncCorrelateFindingAction(mock(Task.class), request, null, listener);
    }

    @SuppressWarnings("unchecked")
    public void testGetTimestampFeature_resourceAlreadyExists_retriesAndProceeds() throws Exception {
        TestSetup s = buildTestSetup();
        ActionListener<SubscribeFindingsResponse> listener = mock(ActionListener.class);
        TransportCorrelateFindingAction.AsyncCorrelateFindingAction asyncAction =
                buildAsyncAction(s, listener);

        when(s.correlationIndices.correlationMetadataIndexExists()).thenReturn(false).thenReturn(true);
        doAnswer(
                        inv -> {
                            ActionListener<CreateIndexResponse> l = inv.getArgument(0);
                            l.onFailure(
                                    new ResourceAlreadyExistsException(
                                            CorrelationIndices.CORRELATION_METADATA_INDEX));
                            return null;
                        })
                .when(s.correlationIndices)
                .initCorrelationMetadataIndex(any());

        asyncAction.getTimestampFeature(
                "windows", Collections.emptyMap(), null, Collections.emptyList());

        ArgumentCaptor<SearchRequest> captor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(s.client).search(captor.capture(), any());
        assertTrue(
                "Expected search against metadata index",
                Arrays.asList(captor.getValue().indices())
                        .contains(CorrelationIndices.CORRELATION_METADATA_INDEX));
        verify(listener, never()).onFailure(any());
    }

    @SuppressWarnings("unchecked")
    public void testGetTimestampFeature_otherException_callsOnFailures() throws Exception {
        TestSetup s = buildTestSetup();
        ActionListener<SubscribeFindingsResponse> listener = mock(ActionListener.class);
        TransportCorrelateFindingAction.AsyncCorrelateFindingAction asyncAction =
                buildAsyncAction(s, listener);

        when(s.correlationIndices.correlationMetadataIndexExists()).thenReturn(false);
        doAnswer(
                        inv -> {
                            ActionListener<CreateIndexResponse> l = inv.getArgument(0);
                            l.onFailure(new RuntimeException("unexpected storage failure"));
                            return null;
                        })
                .when(s.correlationIndices)
                .initCorrelationMetadataIndex(any());

        asyncAction.getTimestampFeature(
                "windows", Collections.emptyMap(), null, Collections.emptyList());

        verify(listener).onFailure(any());
        verify(s.client, never()).search(any(), any());
    }

    @SuppressWarnings("unchecked")
    public void testDoExecute_metadataIndexAlreadyExists_callsStart() throws Exception {
        TestSetup s = buildTestSetup();
        when(s.correlationIndices.correlationIndexExists()).thenReturn(false);
        when(s.correlationIndices.correlationMetadataIndexExists()).thenReturn(true);
        doAnswer(
                        inv -> {
                            ActionListener<CreateIndexResponse> l = inv.getArgument(0);
                            l.onResponse(new CreateIndexResponse(true, true, "history-index-1"));
                            return null;
                        })
                .when(s.correlationIndices)
                .initCorrelationIndex(any());

        when(s.detectorIndices.detectorIndexExists()).thenReturn(true);

        Finding finding =
                new Finding(
                        "finding-1",
                        List.of("doc-1"),
                        List.of("doc-1"),
                        "monitor-1",
                        "monitor-name",
                        "test-index",
                        Collections.emptyList(),
                        Instant.now(),
                        "high");
        PublishFindingsRequest findingsRequest = new PublishFindingsRequest("monitor-1", finding);
        ActionListener<SubscribeFindingsResponse> listener = mock(ActionListener.class);

        s.transportAction.execute(mock(Task.class), findingsRequest, listener);

        ArgumentCaptor<SearchRequest> captor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(s.client).search(captor.capture(), any());
        assertEquals(Detector.DETECTORS_INDEX, captor.getValue().indices()[0]);
    }
}
