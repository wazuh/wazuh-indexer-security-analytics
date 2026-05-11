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

import org.opensearch.common.unit.TimeValue;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.opensearch.securityanalytics.TestHelpers.randomCustomLogType;

public class LogTypeListCacheTests extends OpenSearchTestCase {

    public void testHitAndMiss() {
        LogTypeListCache cache = new LogTypeListCache(TimeValue.timeValueMinutes(5));
        Map<String, CustomLogType> snapshot =
                Map.of("system-activity", randomCustomLogType("system-activity", null, null, null));

        assertTrue(cache.get().isEmpty());

        cache.put(snapshot);
        Optional<Map<String, CustomLogType>> hit = cache.get();
        assertTrue(hit.isPresent());
        assertSame(snapshot, hit.get());
    }

    public void testTtlExpiry() {
        AtomicLong now = new AtomicLong(0);
        LogTypeListCache cache = new LogTypeListCache(TimeValue.timeValueSeconds(10), now::get);
        Map<String, CustomLogType> snapshot = Map.of("a", randomCustomLogType("a", null, null, null));

        cache.put(snapshot);
        assertTrue(cache.get().isPresent());

        now.addAndGet(TimeValue.timeValueSeconds(9).nanos());
        assertTrue(cache.get().isPresent());

        now.addAndGet(TimeValue.timeValueSeconds(2).nanos());
        assertTrue(cache.get().isEmpty());
    }

    public void testInvalidate() {
        LogTypeListCache cache = new LogTypeListCache(TimeValue.timeValueMinutes(5));
        cache.put(Map.of("a", randomCustomLogType("a", null, null, null)));
        assertTrue(cache.get().isPresent());

        cache.invalidate();
        assertTrue(cache.get().isEmpty());
    }

    public void testZeroTtlDisablesCache() {
        LogTypeListCache cache = new LogTypeListCache(TimeValue.timeValueMillis(0));
        cache.put(Map.of("a", randomCustomLogType("a", null, null, null)));
        assertTrue(cache.get().isEmpty());
    }

    public void testSetTtlClearsCacheWhenDisabled() {
        LogTypeListCache cache = new LogTypeListCache(TimeValue.timeValueMinutes(5));
        cache.put(Map.of("a", randomCustomLogType("a", null, null, null)));
        assertTrue(cache.get().isPresent());

        cache.setTtl(TimeValue.timeValueMillis(0));
        assertTrue(cache.get().isEmpty());
    }

    public void testNullPutIsNoOp() {
        LogTypeListCache cache = new LogTypeListCache(TimeValue.timeValueMinutes(5));
        cache.put(null);
        assertTrue(cache.get().isEmpty());
    }
}
