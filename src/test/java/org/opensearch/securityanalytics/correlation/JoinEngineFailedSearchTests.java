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
package org.opensearch.securityanalytics.correlation;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.document.DocumentField;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.commons.alerting.action.PublishFindingsRequest;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.correlation.alert.notifications.NotificationService;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.CorrelationQuery;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.transport.TransportCorrelateFindingAction;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Every step of the correlation join sends one multi-search and reads the answers by position: the
 * n-th answer belongs to the n-th log type, rule or category that was searched. These tests fail
 * the first search of a step and check that the answers after it are still read as their own.
 */
public class JoinEngineFailedSearchTests extends OpenSearchTestCase {

    private static final String DETECTOR_TYPE = "network";

    private static final List<String> CATEGORIES = List.of(DETECTOR_TYPE, "windows", "linux");

    private Client client;

    private TransportCorrelateFindingAction.AsyncCorrelateFindingAction action;

    private LogTypeService logTypeService;

    private CorrelationRulesCache rulesCache;

    private Finding finding;

    private Detector detector;

    /** Every multi-search the engine sent, in order. */
    private List<MultiSearchRequest> searches;

    /** Answers to the multi-searches, in order. A search with no answer left is not answered. */
    private Deque<Function<MultiSearchRequest, MultiSearchResponse.Item[]>> answers;

    @Override
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
        this.action = mock(TransportCorrelateFindingAction.AsyncCorrelateFindingAction.class);
        this.logTypeService = mock(LogTypeService.class);
        this.rulesCache = new CorrelationRulesCache(TimeValue.timeValueMinutes(5));
        this.finding =
                new Finding(
                        "finding-1",
                        List.of("doc-1"),
                        List.of("doc-1"),
                        "monitor-1",
                        "monitor-name",
                        eventsIndex(DETECTOR_TYPE),
                        List.of(
                                new DocLevelQuery(
                                        "query-1",
                                        "Failed logon",
                                        List.of(),
                                        "event.code: \"4625\"",
                                        List.of("attack.t1110"))),
                        Instant.now(),
                        null);
        this.detector = TestHelpers.randomDetector(List.of(), DETECTOR_TYPE);
        this.searches = new ArrayList<>();
        this.answers = new ArrayDeque<>();

        doAnswer(
                        inv -> {
                            MultiSearchRequest request = inv.getArgument(0);
                            this.searches.add(request);
                            Function<MultiSearchRequest, MultiSearchResponse.Item[]> answer = this.answers.poll();
                            if (answer != null) {
                                ((ActionListener<MultiSearchResponse>) inv.getArgument(1))
                                        .onResponse(new MultiSearchResponse(answer.apply(request), 1L));
                            }
                            return null;
                        })
                .when(this.client)
                .multiSearch(any(), any());
    }

    private JoinEngine engine(boolean autoCorrelations) {
        return new JoinEngine(
                this.client,
                new PublishFindingsRequest("monitor-1", this.finding),
                TestHelpers.xContentRegistry(),
                TimeValue.timeValueMinutes(5).millis(),
                TimeValue.timeValueSeconds(60),
                this.action,
                this.logTypeService,
                autoCorrelations,
                mock(CorrelationAlertService.class),
                mock(NotificationService.class),
                null,
                this.rulesCache);
    }

    private static String eventsIndex(String category) {
        return "wazuh-events-v5-" + category;
    }

    /** The category whose events a search reads. */
    private static String eventsCategory(SearchRequest request) {
        return CATEGORIES.stream()
                .filter(category -> eventsIndex(category).equals(request.indices()[0]))
                .findFirst()
                .orElseThrow();
    }

    /** The category whose findings a search reads. */
    private static String findingsCategory(SearchRequest request) {
        return CATEGORIES.stream()
                .filter(
                        category ->
                                DetectorMonitorConfig.getAllFindingsIndicesPattern(category)
                                        .equals(request.indices()[0]))
                .findFirst()
                .orElseThrow();
    }

    /** A rule joining the detector's category on a field with a query on each other category. */
    private static CorrelationRule ruleAcrossCategories() {
        return new CorrelationRule(
                "rule-1",
                1L,
                "Same user across categories",
                List.of(
                        new CorrelationQuery(eventsIndex(DETECTOR_TYPE), null, DETECTOR_TYPE, "user.name"),
                        new CorrelationQuery(eventsIndex("windows"), "event.code:4625", "windows", null),
                        new CorrelationQuery(eventsIndex("linux"), "process.name:sshd", "linux", null)),
                300000L,
                null);
    }

    /** A rule joining the detector's category on {@code field}. */
    private static CorrelationRule ruleOnField(String id, String field) {
        return new CorrelationRule(
                id,
                1L,
                "Join on " + field,
                List.of(new CorrelationQuery(eventsIndex(DETECTOR_TYPE), null, DETECTOR_TYPE, field)),
                300000L,
                null);
    }

    private static SearchHit hitWithField(String id, String field, Object value) {
        return new SearchHit(0, id, Map.of(field, new DocumentField(field, List.of(value))), Map.of());
    }

    private static SearchHit hitWithSource(String id, String source) {
        SearchHit hit = new SearchHit(0, id, Map.of(), Map.of());
        hit.sourceRef(new BytesArray(source));
        return hit;
    }

    private static SearchResponse searchResponse(SearchHit... hits) {
        SearchResponse response = mock(SearchResponse.class);
        when(response.getHits())
                .thenReturn(
                        new SearchHits(hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 1.0f));
        return response;
    }

    private static MultiSearchResponse.Item failed() {
        return new MultiSearchResponse.Item(null, new IllegalStateException("search was cancelled"));
    }

    /** Answers every search of a step with the hit {@code hit} gives for it. */
    private static Function<MultiSearchRequest, MultiSearchResponse.Item[]> allFind(
            Function<SearchRequest, SearchHit> hit) {
        return request ->
                request.requests().stream()
                        .map(search -> new MultiSearchResponse.Item(searchResponse(hit.apply(search)), null))
                        .toArray(MultiSearchResponse.Item[]::new);
    }

    /** Like {@link #allFind}, but the first search of the step fails. */
    private static Function<MultiSearchRequest, MultiSearchResponse.Item[]> firstFails(
            Function<SearchRequest, SearchHit> hit) {
        return request -> {
            MultiSearchResponse.Item[] items = allFind(hit).apply(request);
            items[0] = failed();
            return items;
        };
    }

    /** Fails every search of a step. */
    private static Function<MultiSearchRequest, MultiSearchResponse.Item[]> allFail() {
        return request ->
                request.requests().stream()
                        .map(search -> failed())
                        .toArray(MultiSearchResponse.Item[]::new);
    }

    /** What each search of a step asks, by the category {@code category} reads from it. */
    private static Map<String, String> queriesByCategory(
            MultiSearchRequest step, Function<SearchRequest, String> category) {
        Map<String, String> queries = new HashMap<>();
        for (SearchRequest search : step.requests()) {
            queries.put(category.apply(search), search.source().query().toString());
        }
        return queries;
    }

    /** The categories of a step's searches, without the first one. */
    private static List<String> categoriesAfterTheFirst(
            MultiSearchRequest step, Function<SearchRequest, String> category) {
        return step.requests().stream().skip(1).map(category).collect(Collectors.toList());
    }

    /**
     * Automatic correlations search the findings of every log type. The findings of the log type
     * whose search failed are unknown; the ones found for the next log type belong to that one.
     */
    @SuppressWarnings("unchecked")
    public void testAutoCorrelations_failedLogTypeDoesNotTakeTheNextOnesFindings() {
        SearchResponse logTypes =
                searchResponse(
                        hitWithSource("log-type-1", "{\"name\":\"linux\"}"),
                        hitWithSource("log-type-2", "{\"name\":\"windows\"}"));
        doAnswer(
                        inv -> {
                            ((ActionListener<SearchResponse>) inv.getArgument(1)).onResponse(logTypes);
                            return null;
                        })
                .when(this.logTypeService)
                .searchLogTypes(any(), any());
        this.rulesCache.put(DETECTOR_TYPE, List.of());
        this.answers.add(
                firstFails(
                        search -> hitWithSource("finding-2", "{\"queries\":[{\"tags\":[\"attack.t1110\"]}]}")));

        engine(true).onSearchDetectorResponse(this.detector, this.finding);

        verify(this.action)
                .getTimestampFeature(
                        DETECTOR_TYPE, Map.of("windows", List.of("finding-2")), null, List.of());
        verify(this.action, never()).onFailures(any());
    }

    /**
     * The events of the finding are searched once per rule. A rule whose search failed is left out;
     * the events found for the next rule are joined on that rule's field, not on the failed one's.
     */
    public void testRuleSearch_failedRuleDoesNotTakeTheNextOnesEvents() {
        this.rulesCache.put(
                DETECTOR_TYPE,
                List.of(ruleOnField("rule-1", "source.ip"), ruleOnField("rule-2", "user.name")));
        this.answers.add(firstFails(search -> hitWithField("doc-1", "user.name", "alice")));
        // No findings to join with, which ends the join with the rules that matched.
        this.answers.add(allFail());

        engine(false).onSearchDetectorResponse(this.detector, this.finding);

        verify(this.action).getTimestampFeature(DETECTOR_TYPE, null, this.finding, List.of("rule-2"));
        verify(this.action, never()).onFailures(any());
    }

    /**
     * The findings of each category in the rule are searched for the events they came from. A
     * category whose search failed is left out; each of the others is then asked about its own
     * events, in its own index.
     */
    public void testFindingsSearch_failedCategoryDoesNotTakeTheNextOnesEvents() {
        this.rulesCache.put(DETECTOR_TYPE, List.of(ruleAcrossCategories()));
        this.answers.add(allFind(search -> hitWithField("doc-1", "user.name", "alice")));
        this.answers.add(
                firstFails(
                        search ->
                                hitWithField(
                                        "finding-" + findingsCategory(search),
                                        "correlated_doc_ids",
                                        "doc-" + findingsCategory(search))));

        engine(false).onSearchDetectorResponse(this.detector, this.finding);

        assertEquals("the join reached the search of the related events", 3, this.searches.size());
        List<String> answered =
                categoriesAfterTheFirst(
                        this.searches.get(1), JoinEngineFailedSearchTests::findingsCategory);
        Map<String, String> eventSearches =
                queriesByCategory(this.searches.get(2), JoinEngineFailedSearchTests::eventsCategory);
        assertEquals(new HashSet<>(answered), eventSearches.keySet());
        for (String category : answered) {
            assertTrue(
                    category + " is asked about its own events",
                    eventSearches.get(category).contains("doc-" + category));
        }
    }

    /**
     * The related events of each category are filtered by the rule's query. A category whose search
     * failed is left out; the events that passed for each of the others are looked up in that
     * category's findings.
     */
    public void testEventsSearch_failedCategoryDoesNotTakeTheNextOnesEvents() {
        this.rulesCache.put(DETECTOR_TYPE, List.of(ruleAcrossCategories()));
        this.answers.add(allFind(search -> hitWithField("doc-1", "user.name", "alice")));
        this.answers.add(
                allFind(
                        search ->
                                hitWithField(
                                        "finding-" + findingsCategory(search),
                                        "correlated_doc_ids",
                                        "doc-" + findingsCategory(search))));
        this.answers.add(
                firstFails(
                        search -> new SearchHit(0, "doc-" + eventsCategory(search), Map.of(), Map.of())));

        engine(false).onSearchDetectorResponse(this.detector, this.finding);

        assertEquals("the join reached the search of the correlated findings", 4, this.searches.size());
        List<String> answered =
                categoriesAfterTheFirst(this.searches.get(2), JoinEngineFailedSearchTests::eventsCategory);
        Map<String, String> findingSearches =
                queriesByCategory(this.searches.get(3), JoinEngineFailedSearchTests::findingsCategory);
        assertEquals(new HashSet<>(answered), findingSearches.keySet());
        for (String category : answered) {
            assertTrue(
                    category + " findings are searched for its own events",
                    findingSearches.get(category).contains("doc-" + category));
        }
    }
}
