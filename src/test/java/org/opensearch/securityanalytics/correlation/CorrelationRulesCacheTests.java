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
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.test.OpenSearchTestCase;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.opensearch.securityanalytics.TestHelpers.randomCorrelationRule;

public class CorrelationRulesCacheTests extends OpenSearchTestCase {

    public void testHitAndMiss() {
        CorrelationRulesCache cache = new CorrelationRulesCache(TimeValue.timeValueMinutes(5));
        List<CorrelationRule> rules =
                List.of(randomCorrelationRule("rule-a"), randomCorrelationRule("rule-b"));

        assertTrue(cache.get("network").isEmpty());

        cache.put("network", rules);
        Optional<List<CorrelationRule>> hit = cache.get("network");
        assertTrue(hit.isPresent());
        assertEquals(2, hit.get().size());

        assertTrue(cache.get("system-activity").isEmpty());
    }

    public void testStoredListIsImmutable() {
        CorrelationRulesCache cache = new CorrelationRulesCache(TimeValue.timeValueMinutes(5));
        List<CorrelationRule> mutable =
                new java.util.ArrayList<>(List.of(randomCorrelationRule("rule-a")));
        cache.put("network", mutable);

        mutable.add(randomCorrelationRule("rule-b"));
        assertEquals(
                "cache should snapshot input list, not share reference",
                1,
                cache.get("network").get().size());
    }

    public void testTtlExpiry() {
        AtomicLong now = new AtomicLong(0);
        CorrelationRulesCache cache =
                new CorrelationRulesCache(TimeValue.timeValueSeconds(10), now::get);
        cache.put("network", List.of(randomCorrelationRule("rule-a")));
        assertTrue(cache.get("network").isPresent());

        now.addAndGet(TimeValue.timeValueSeconds(9).nanos());
        assertTrue(cache.get("network").isPresent());

        now.addAndGet(TimeValue.timeValueSeconds(2).nanos());
        assertTrue(cache.get("network").isEmpty());
        assertEquals(0, cache.size());
    }

    public void testInvalidate() {
        CorrelationRulesCache cache = new CorrelationRulesCache(TimeValue.timeValueMinutes(5));
        cache.put("network", List.of(randomCorrelationRule("a")));
        cache.put("system-activity", List.of(randomCorrelationRule("b")));

        cache.invalidate("network");
        assertTrue(cache.get("network").isEmpty());
        assertTrue(cache.get("system-activity").isPresent());

        cache.invalidateAll();
        assertEquals(0, cache.size());
    }

    public void testZeroTtlDisablesCache() {
        CorrelationRulesCache cache = new CorrelationRulesCache(TimeValue.timeValueMillis(0));
        cache.put("network", List.of(randomCorrelationRule("a")));
        assertEquals(0, cache.size());
        assertTrue(cache.get("network").isEmpty());
    }

    public void testSetTtlClearsCacheWhenDisabled() {
        CorrelationRulesCache cache = new CorrelationRulesCache(TimeValue.timeValueMinutes(5));
        cache.put("network", List.of(randomCorrelationRule("a")));
        assertEquals(1, cache.size());

        cache.setTtl(TimeValue.timeValueMillis(0));
        assertEquals(0, cache.size());
    }
}
