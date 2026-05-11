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
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.test.OpenSearchTestCase;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.opensearch.securityanalytics.TestHelpers.randomDetector;

public class DetectorLookupCacheTests extends OpenSearchTestCase {

    public void testHitAndMiss() {
        DetectorLookupCache cache = new DetectorLookupCache(TimeValue.timeValueMinutes(5));
        Detector detector = randomDetector(List.of(UUID.randomUUID().toString()));

        assertTrue(cache.get("monitor-1").isEmpty());

        cache.put("monitor-1", detector);
        Optional<Detector> hit = cache.get("monitor-1");
        assertTrue(hit.isPresent());
        assertSame(detector, hit.get());

        assertTrue(cache.get("monitor-2").isEmpty());
    }

    public void testTtlExpiry() {
        AtomicLong now = new AtomicLong(0);
        DetectorLookupCache cache = new DetectorLookupCache(TimeValue.timeValueSeconds(10), now::get);
        Detector detector = randomDetector(List.of(UUID.randomUUID().toString()));

        cache.put("monitor-1", detector);
        assertTrue(cache.get("monitor-1").isPresent());

        now.addAndGet(TimeValue.timeValueSeconds(9).nanos());
        assertTrue("entry should still be live before TTL", cache.get("monitor-1").isPresent());

        now.addAndGet(TimeValue.timeValueSeconds(2).nanos());
        assertTrue("entry should be expired after TTL", cache.get("monitor-1").isEmpty());
        assertEquals("expired entry should be evicted", 0, cache.size());
    }

    public void testInvalidate() {
        DetectorLookupCache cache = new DetectorLookupCache(TimeValue.timeValueMinutes(5));
        Detector detector = randomDetector(List.of(UUID.randomUUID().toString()));

        cache.put("monitor-1", detector);
        cache.put("monitor-2", detector);

        cache.invalidate("monitor-1");
        assertTrue(cache.get("monitor-1").isEmpty());
        assertTrue(cache.get("monitor-2").isPresent());

        cache.invalidateAll();
        assertTrue(cache.get("monitor-2").isEmpty());
        assertEquals(0, cache.size());
    }

    public void testZeroTtlDisablesCache() {
        DetectorLookupCache cache = new DetectorLookupCache(TimeValue.timeValueMillis(0));
        Detector detector = randomDetector(List.of(UUID.randomUUID().toString()));

        cache.put("monitor-1", detector);
        assertEquals("put should be a no-op when ttl=0", 0, cache.size());
        assertTrue(cache.get("monitor-1").isEmpty());
    }

    public void testSetTtlClearsCacheWhenDisabled() {
        DetectorLookupCache cache = new DetectorLookupCache(TimeValue.timeValueMinutes(5));
        Detector detector = randomDetector(List.of(UUID.randomUUID().toString()));

        cache.put("monitor-1", detector);
        assertEquals(1, cache.size());

        cache.setTtl(TimeValue.timeValueMillis(0));
        assertEquals("disabling cache should evict all entries", 0, cache.size());
        assertTrue(cache.get("monitor-1").isEmpty());
    }

    public void testNullDetectorIsNotStored() {
        DetectorLookupCache cache = new DetectorLookupCache(TimeValue.timeValueMinutes(5));
        cache.put("monitor-1", null);
        assertEquals(0, cache.size());
        assertTrue(cache.get("monitor-1").isEmpty());
    }

    public void testConcurrentPutAndGet() throws Exception {
        DetectorLookupCache cache = new DetectorLookupCache(TimeValue.timeValueMinutes(5));
        Detector detector = randomDetector(List.of(UUID.randomUUID().toString()));
        int threads = 8;
        int opsPerThread = 1000;

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);

        for (int t = 0; t < threads; t++) {
            int finalT = t;
            pool.submit(
                    () -> {
                        try {
                            start.await();
                            for (int i = 0; i < opsPerThread; i++) {
                                String key = "monitor-" + (finalT % 4);
                                cache.put(key, detector);
                                cache.get(key);
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } finally {
                            done.countDown();
                        }
                    });
        }

        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdownNow();

        assertEquals(4, cache.size());
        for (int i = 0; i < 4; i++) {
            assertSame(detector, cache.get("monitor-" + i).orElse(null));
        }
    }
}
