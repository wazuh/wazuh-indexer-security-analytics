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

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.securityanalytics.action.WRefreshDetectorsRequest;
import com.wazuh.securityanalytics.action.WRefreshDetectorsResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** The detector refresh reads the detectors as the plugin and answers in the caller's context. */
public class WTransportRefreshDetectorsActionTests extends OpenSearchTestCase {

    private static final String CALLER = "caller";

    private ThreadContext threadContext;
    private Client client;
    private WTransportRefreshDetectorsAction action;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.threadContext = new ThreadContext(Settings.EMPTY);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(this.threadContext);
        this.client = mock(Client.class);
        this.action =
                new WTransportRefreshDetectorsAction(
                        mock(TransportService.class),
                        new ActionFilters(Collections.emptySet()),
                        this.client,
                        NamedXContentRegistry.EMPTY,
                        threadPool);
    }

    private static SearchResponse noDetectors() {
        SearchResponse response = mock(SearchResponse.class);
        when(response.getHits()).thenReturn(SearchHits.empty());
        return response;
    }

    /** Records the caller seen by the search and by the listener. */
    private AtomicReference<String> execute(
            AtomicReference<String> seenBySearch,
            AtomicReference<ActionListener<SearchResponse>> searchListener) {
        doAnswer(
                        invocation -> {
                            seenBySearch.set(this.threadContext.getTransient(CALLER));
                            searchListener.set(invocation.getArgument(1));
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any());
        AtomicReference<String> seenByListener = new AtomicReference<>("not called");
        this.action.doExecute(
                null,
                new WRefreshDetectorsRequest(List.of("rule-1")),
                new ActionListener<WRefreshDetectorsResponse>() {
                    @Override
                    public void onResponse(WRefreshDetectorsResponse response) {
                        seenByListener.set(threadContext.getTransient(CALLER));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        seenByListener.set(threadContext.getTransient(CALLER));
                    }
                });
        return seenByListener;
    }

    public void testRefreshReadsAsThePluginAndHandsTheThreadBack() {
        this.threadContext.putTransient(CALLER, "user-a");
        AtomicReference<String> seenBySearch = new AtomicReference<>("not called");
        AtomicReference<ActionListener<SearchResponse>> searchListener = new AtomicReference<>();

        AtomicReference<String> seenByListener = this.execute(seenBySearch, searchListener);

        assertNull("the detectors are read as the plugin", seenBySearch.get());
        assertEquals(
                "the caller's thread is handed back in its context",
                "user-a",
                this.threadContext.getTransient(CALLER));
        searchListener.get().onResponse(noDetectors());
        assertEquals("user-a", seenByListener.get());
    }

    public void testAnswerArrivingInAnotherContextReachesTheCallerInItsOwn() {
        this.threadContext.putTransient(CALLER, "user-a");
        AtomicReference<String> seenBySearch = new AtomicReference<>("not called");
        AtomicReference<ActionListener<SearchResponse>> searchListener = new AtomicReference<>();
        AtomicReference<String> seenByListener = this.execute(seenBySearch, searchListener);

        // The search answers later, on a thread holding another context.
        try (ThreadContext.StoredContext ignored = this.threadContext.stashContext()) {
            this.threadContext.putTransient(CALLER, "plugin-thread");
            searchListener.get().onResponse(noDetectors());
        }
        assertEquals("user-a", seenByListener.get());
    }

    public void testFailureArrivingInAnotherContextReachesTheCallerInItsOwn() {
        this.threadContext.putTransient(CALLER, "user-a");
        AtomicReference<ActionListener<SearchResponse>> searchListener = new AtomicReference<>();
        AtomicReference<String> seenByListener = this.execute(new AtomicReference<>(), searchListener);

        try (ThreadContext.StoredContext ignored = this.threadContext.stashContext()) {
            this.threadContext.putTransient(CALLER, "plugin-thread");
            searchListener.get().onFailure(new IllegalStateException("detectors index unavailable"));
        }
        assertEquals("user-a", seenByListener.get());
    }
}
