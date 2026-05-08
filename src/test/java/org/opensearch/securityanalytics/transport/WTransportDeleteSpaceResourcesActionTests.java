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

import org.opensearch.OpenSearchException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

public class WTransportDeleteSpaceResourcesActionTests extends OpenSearchTestCase {

    /**
     * Captures the outcome of an {@link ActionListener} so tests can assert on the value or failure
     * delivered to it.
     */
    private static final class CapturingListener<T> implements ActionListener<T> {
        final AtomicReference<T> response = new AtomicReference<>();
        final AtomicReference<Exception> failure = new AtomicReference<>();

        @Override
        public void onResponse(T value) {
            response.set(value);
        }

        @Override
        public void onFailure(Exception e) {
            failure.set(e);
        }
    }

    public void testResolveOrFail_indexNotFound_resolvesWithIntegerEmptyValue() {
        CapturingListener<Integer> listener = new CapturingListener<>();

        WTransportDeleteSpaceResourcesAction.resolveOrFail(
                new IndexNotFoundException("missing"), 0, listener);

        assertEquals(Integer.valueOf(0), listener.response.get());
        assertNull(listener.failure.get());
    }

    public void testResolveOrFail_indexNotFound_resolvesWithEmptyList() {
        CapturingListener<List<String>> listener = new CapturingListener<>();

        WTransportDeleteSpaceResourcesAction.resolveOrFail(
                new IndexNotFoundException("missing"), Collections.emptyList(), listener);

        assertNotNull(listener.response.get());
        assertTrue(listener.response.get().isEmpty());
        assertNull(listener.failure.get());
    }

    public void testResolveOrFail_indexNotFoundAsCause_resolves() {
        CapturingListener<Integer> listener = new CapturingListener<>();
        Exception wrapped = new OpenSearchException("wrap", new IndexNotFoundException("missing"));

        WTransportDeleteSpaceResourcesAction.resolveOrFail(wrapped, 0, listener);

        assertEquals(Integer.valueOf(0), listener.response.get());
        assertNull(listener.failure.get());
    }

    public void testResolveOrFail_otherException_propagatesFailure() {
        CapturingListener<Integer> listener = new CapturingListener<>();
        Exception unrelated = new IllegalStateException("boom");

        WTransportDeleteSpaceResourcesAction.resolveOrFail(unrelated, 0, listener);

        assertNull(listener.response.get());
        assertSame(unrelated, listener.failure.get());
    }

    /**
     * Regression test for the {@code ClassCastException} reported on first-startup space cleanup.
     * Previously the helper unconditionally returned an {@code ArrayList} and relied on a dead {@code
     * catch (ClassCastException)} block, so an {@code Integer}-typed listener received a value of the
     * wrong runtime type and the cast surfaced later as a partial-failure.
     */
    public void testResolveOrFail_indexNotFound_integerListenerReceivesInteger() {
        CapturingListener<Integer> listener = new CapturingListener<>();

        WTransportDeleteSpaceResourcesAction.resolveOrFail(
                new IndexNotFoundException("missing"), 0, listener);

        Object delivered = listener.response.get();
        assertNotNull(delivered);
        assertTrue(
                "expected Integer but got " + delivered.getClass().getName(), delivered instanceof Integer);
    }
}
