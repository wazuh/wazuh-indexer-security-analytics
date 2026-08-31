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

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.model.Value;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.ExceptionChecker;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TransportIndexDetectorActionTests extends OpenSearchTestCase {

    private static class CapturingListener implements ActionListener<IndexDetectorResponse> {
        private Exception failure;

        @Override
        public void onResponse(IndexDetectorResponse indexDetectorResponse) {
            // no-op
        }

        @Override
        public void onFailure(Exception e) {
            this.failure = e;
        }
    }

    private TransportIndexDetectorAction createAction(Client client) {
        TransportService transportService = mock(TransportService.class);
        ClusterService clusterService = mock(ClusterService.class);
        DetectorIndices detectorIndices = mock(DetectorIndices.class);
        ThreadPool threadPool = mock(ThreadPool.class);

        Set<Setting<?>> settings =
                new HashSet<>(
                        Arrays.asList(
                                SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES,
                                SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE,
                                SecurityAnalyticsSettings.ENABLE_DETECTORS_WITH_DEDICATED_QUERY_INDICES,
                                SecurityAnalyticsSettings.MAX_DETECTORS,
                                SecurityAnalyticsSettings.MAX_RULES_PER_DETECTOR));
        when(clusterService.getClusterSettings())
                .thenReturn(new ClusterSettings(Settings.EMPTY, settings));
        when(detectorIndices.getThreadPool()).thenReturn(threadPool);

        return new TransportIndexDetectorAction(
                transportService,
                client,
                new ActionFilters(Collections.emptySet()),
                mock(NamedXContentRegistry.class),
                detectorIndices,
                mock(RuleTopicIndices.class),
                mock(RuleIndices.class),
                mock(MapperService.class),
                clusterService,
                Settings.EMPTY,
                mock(NamedWriteableRegistry.class),
                mock(LogTypeService.class),
                mock(IndexNameExpressionResolver.class),
                mock(ExceptionChecker.class));
    }

    private static IndexDetectorRequest requestWithIndices(String... indices) {
        DetectorInput input =
                new DetectorInput(
                        "test", List.of(indices), Collections.emptyList(), Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));
        return new IndexDetectorRequest(
                "", WriteRequest.RefreshPolicy.IMMEDIATE, RestRequest.Method.POST, detector);
    }

    private static void invokeCheckIndicesAndExecute(
            TransportIndexDetectorAction action,
            IndexDetectorRequest request,
            ActionListener<IndexDetectorResponse> listener)
            throws Exception {
        Method method =
                TransportIndexDetectorAction.class.getDeclaredMethod(
                        "checkIndicesAndExecute",
                        org.opensearch.tasks.Task.class,
                        IndexDetectorRequest.class,
                        ActionListener.class,
                        org.opensearch.commons.authuser.User.class);
        method.setAccessible(true);
        method.invoke(action, null, request, listener, null);
    }

    public void testValidateRuleCount_withinLimit_returnsNull() {
        List<DetectorRule> rules = List.of(new DetectorRule("rule-1"), new DetectorRule("rule-2"));
        DetectorInput input =
                new DetectorInput("test", List.of("index-1"), Collections.emptyList(), rules);
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(
                TransportIndexDetectorAction.validateRuleCount(
                        detector, SecurityAnalyticsSettings.DEFAULT_MAX_RULES_PER_DETECTOR));
    }

    public void testValidateRuleCount_atLimit_returnsNull() {
        List<DetectorRule> rules =
                IntStream.rangeClosed(1, SecurityAnalyticsSettings.DEFAULT_MAX_RULES_PER_DETECTOR)
                        .mapToObj(i -> new DetectorRule("rule-" + i))
                        .collect(Collectors.toList());
        DetectorInput input =
                new DetectorInput("test", List.of("index-1"), Collections.emptyList(), rules);
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(
                TransportIndexDetectorAction.validateRuleCount(
                        detector, SecurityAnalyticsSettings.DEFAULT_MAX_RULES_PER_DETECTOR));
    }

    public void testValidateRuleCount_exceedsLimit_returnsError() {
        int overLimit = SecurityAnalyticsSettings.DEFAULT_MAX_RULES_PER_DETECTOR + 1;
        List<DetectorRule> rules =
                IntStream.rangeClosed(1, overLimit)
                        .mapToObj(i -> new DetectorRule("rule-" + i))
                        .collect(Collectors.toList());
        DetectorInput input =
                new DetectorInput("test", List.of("index-1"), Collections.emptyList(), rules);
        Detector detector = randomDetectorWithInputs(List.of(input));

        String error =
                TransportIndexDetectorAction.validateRuleCount(
                        detector, SecurityAnalyticsSettings.DEFAULT_MAX_RULES_PER_DETECTOR);
        assertNotNull(error);
        assertTrue(
                error.contains(
                        "more than " + SecurityAnalyticsSettings.DEFAULT_MAX_RULES_PER_DETECTOR + " rules"));
        assertTrue(error.contains(String.valueOf(overLimit)));
    }

    public void testValidateRuleCount_customRulesExceedsLimit_returnsError() {
        List<DetectorRule> customRules =
                IntStream.rangeClosed(1, SecurityAnalyticsSettings.DEFAULT_MAX_RULES_PER_DETECTOR + 1)
                        .mapToObj(i -> new DetectorRule("custom-rule-" + i))
                        .collect(Collectors.toList());
        DetectorInput input =
                new DetectorInput("test", List.of("index-1"), customRules, Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        String error =
                TransportIndexDetectorAction.validateRuleCount(
                        detector, SecurityAnalyticsSettings.DEFAULT_MAX_RULES_PER_DETECTOR);
        assertNotNull(error);
        assertTrue(
                error.contains(
                        "more than " + SecurityAnalyticsSettings.DEFAULT_MAX_RULES_PER_DETECTOR + " rules"));
    }

    public void testValidateRuleCount_emptyRules_returnsNull() {
        DetectorInput input =
                new DetectorInput(
                        "test", List.of("index-1"), Collections.emptyList(), Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(
                TransportIndexDetectorAction.validateRuleCount(
                        detector, SecurityAnalyticsSettings.DEFAULT_MAX_RULES_PER_DETECTOR));
    }

    public void testValidateSingleRuleSpace_onlyPrePackaged_returnsNull() {
        List<DetectorRule> prePackaged =
                List.of(new DetectorRule("rule-1"), new DetectorRule("rule-2"));
        DetectorInput input =
                new DetectorInput("test", List.of("index-1"), Collections.emptyList(), prePackaged);
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(TransportIndexDetectorAction.validateSingleRuleSpace(detector));
    }

    public void testValidateSingleRuleSpace_onlyCustom_returnsNull() {
        List<DetectorRule> custom = List.of(new DetectorRule("rule-1"), new DetectorRule("rule-2"));
        DetectorInput input =
                new DetectorInput("test", List.of("index-1"), custom, Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(TransportIndexDetectorAction.validateSingleRuleSpace(detector));
    }

    public void testValidateSingleRuleSpace_bothTypes_returnsError() {
        List<DetectorRule> prePackaged = List.of(new DetectorRule("std-rule-1"));
        List<DetectorRule> custom = List.of(new DetectorRule("custom-rule-1"));
        DetectorInput input = new DetectorInput("test", List.of("index-1"), custom, prePackaged);
        Detector detector = randomDetectorWithInputs(List.of(input));

        String error = TransportIndexDetectorAction.validateSingleRuleSpace(detector);
        assertNotNull(error);
        assertTrue(error.contains("both prepackaged and custom rules"));
    }

    public void testValidateSingleRuleSpace_emptyRules_returnsNull() {
        DetectorInput input =
                new DetectorInput(
                        "test", List.of("index-1"), Collections.emptyList(), Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(TransportIndexDetectorAction.validateSingleRuleSpace(detector));
    }

    public void testValidateSingleRuleSpace_nullRuleLists_returnsNull() {
        DetectorInput input = new DetectorInput("test", List.of("index-1"), null, null);
        Detector detector = randomDetectorWithInputs(List.of(input));

        assertNull(TransportIndexDetectorAction.validateSingleRuleSpace(detector));
    }

    public void testIsRuleEnabled_disabledJson_returnsFalse() {
        String raw = "{\"title\":\"r\",\"enabled\":false,\"detection\":{\"condition\":\"selection\"}}";
        assertFalse(TransportIndexDetectorAction.isRuleEnabled(raw));
    }

    public void testIsRuleEnabled_enabledJson_returnsTrue() {
        String raw = "{\"title\":\"r\",\"enabled\":true,\"detection\":{\"condition\":\"selection\"}}";
        assertTrue(TransportIndexDetectorAction.isRuleEnabled(raw));
    }

    public void testIsRuleEnabled_missingField_returnsTrue() {
        String raw = "{\"title\":\"r\",\"detection\":{\"condition\":\"selection\"}}";
        assertTrue(TransportIndexDetectorAction.isRuleEnabled(raw));
    }

    public void testIsRuleEnabled_blankOrNull_returnsTrue() {
        assertTrue(TransportIndexDetectorAction.isRuleEnabled(null));
        assertTrue(TransportIndexDetectorAction.isRuleEnabled(""));
        assertTrue(TransportIndexDetectorAction.isRuleEnabled("   "));
    }

    public void testIsRuleEnabled_nonJsonYamlBlob_returnsTrue() {
        // Pre-packaged rules loaded from disk are Sigma YAML, not JSON, and carry no enabled field.
        String yaml = "title: r\ndetection:\n  condition: selection\n";
        assertTrue(TransportIndexDetectorAction.isRuleEnabled(yaml));
    }

    public void testIsRuleEnabled_stringBoolean_returnsFalse() {
        String raw = "{\"title\":\"r\",\"enabled\":\"false\"}";
        assertFalse(TransportIndexDetectorAction.isRuleEnabled(raw));
    }

    private static Rule ruleWithBlob(String id, String blob) {
        return new Rule(
                id,
                1L,
                "title",
                "cat",
                "logsource",
                "desc",
                Collections.<Value>emptyList(),
                Collections.<Value>emptyList(),
                "low",
                Collections.<Value>emptyList(),
                "author",
                "stable",
                Instant.now(),
                Collections.<Value>emptyList(),
                Collections.<Value>emptyList(),
                blob,
                Collections.<Value>emptyList());
    }

    public void testFilterEnabledRules_dropsDisabled_keepsEnabledAndUnmarked() {
        List<Pair<String, Rule>> in =
                List.of(
                        Pair.of("a", ruleWithBlob("a", "{\"enabled\":true}")),
                        Pair.of("b", ruleWithBlob("b", "{\"enabled\":false}")),
                        Pair.of("c", ruleWithBlob("c", "{\"title\":\"no-enabled-field\"}")));

        List<Pair<String, Rule>> out = TransportIndexDetectorAction.filterEnabledRules(in);

        List<String> ids = out.stream().map(Pair::getKey).collect(Collectors.toList());
        assertEquals(List.of("a", "c"), ids);
    }

    public void testFilterEnabledRules_allEnabled_returnsAll() {
        List<Pair<String, Rule>> in =
                List.of(
                        Pair.of("a", ruleWithBlob("a", "{\"enabled\":true}")),
                        Pair.of("b", ruleWithBlob("b", "{\"title\":\"x\"}")));

        assertEquals(2, TransportIndexDetectorAction.filterEnabledRules(in).size());
    }

    public void testFilterEnabledRules_empty_returnsEmpty() {
        assertTrue(TransportIndexDetectorAction.filterEnabledRules(Collections.emptyList()).isEmpty());
    }

    public void testCheckIndicesAndExecute_rejectsNonWazuhEventsV5DataSources() throws Exception {
        Client client = mock(Client.class);
        TransportIndexDetectorAction action = createAction(client);
        CapturingListener listener = new CapturingListener();

        invokeCheckIndicesAndExecute(
                action, requestWithIndices("wazuh-events-v5-ok", "other-index"), listener);

        assertNotNull(listener.failure);
        assertTrue(listener.failure instanceof OpenSearchStatusException);
        OpenSearchStatusException ex = (OpenSearchStatusException) listener.failure;
        assertEquals(RestStatus.BAD_REQUEST, ex.status());
        assertTrue(
                ex.getMessage()
                        .contains("Threat detectors can only be created for `wazuh-events-v5` data sources."));
        verify(client, never()).search(any(SearchRequest.class), any(ActionListener.class));
    }

    @SuppressWarnings("unchecked")
    public void testCheckIndicesAndExecute_validPrefixPerformsSourceExistenceCheck()
            throws Exception {
        Client client = mock(Client.class);
        doAnswer(
                        invocation -> {
                            ActionListener<SearchResponse> listener = invocation.getArgument(1);
                            listener.onFailure(new IndexNotFoundException("wazuh-events-v5-missing"));
                            return null;
                        })
                .when(client)
                .search(any(SearchRequest.class), any(ActionListener.class));

        TransportIndexDetectorAction action = createAction(client);
        CapturingListener listener = new CapturingListener();

        invokeCheckIndicesAndExecute(action, requestWithIndices("wazuh-events-v5-missing"), listener);

        verify(client).search(any(SearchRequest.class), any(ActionListener.class));
        assertNotNull(listener.failure);
        assertTrue(listener.failure instanceof OpenSearchException);
        OpenSearchException ex = (OpenSearchException) listener.failure;
        assertEquals(RestStatus.NOT_FOUND, ex.status());
        assertTrue(ex.getMessage().contains("Indices not found wazuh-events-v5-missing"));
    }
}
