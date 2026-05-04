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

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * TTL-bounded cache of correlation rules keyed by detector type. The {@link
 * org.opensearch.securityanalytics.correlation.JoinEngine} performs an identical search against
 * {@code .opensearch-correlation-rules-config} for every finding sharing the same detector type;
 * this cache eliminates that redundancy.
 *
 * <p>A TTL of zero disables the cache.
 */
public final class CorrelationRulesCache {

    private final ConcurrentHashMap<String, Entry> byDetectorType = new ConcurrentHashMap<>();
    private final LongSupplier clock;
    private volatile long ttlNanos;

    public CorrelationRulesCache(TimeValue ttl) {
        this(ttl, System::nanoTime);
    }

    CorrelationRulesCache(TimeValue ttl, LongSupplier clock) {
        this.ttlNanos = ttl.nanos();
        this.clock = clock;
    }

    public Optional<List<CorrelationRule>> get(String detectorType) {
        if (ttlNanos <= 0) {
            return Optional.empty();
        }
        Entry entry = byDetectorType.get(detectorType);
        if (entry == null) {
            return Optional.empty();
        }
        if (clock.getAsLong() > entry.expiresAtNanos) {
            byDetectorType.remove(detectorType, entry);
            return Optional.empty();
        }
        return Optional.of(entry.rules);
    }

    public void put(String detectorType, List<CorrelationRule> rules) {
        long ttl = ttlNanos;
        if (ttl <= 0 || rules == null) {
            return;
        }
        byDetectorType.put(detectorType, new Entry(List.copyOf(rules), clock.getAsLong() + ttl));
    }

    public void invalidate(String detectorType) {
        byDetectorType.remove(detectorType);
    }

    public void invalidateAll() {
        byDetectorType.clear();
    }

    public void setTtl(TimeValue ttl) {
        long newTtl = ttl.nanos();
        this.ttlNanos = newTtl;
        if (newTtl <= 0) {
            byDetectorType.clear();
        }
    }

    int size() {
        return byDetectorType.size();
    }

    private static final class Entry {
        final List<CorrelationRule> rules;
        final long expiresAtNanos;

        Entry(List<CorrelationRule> rules, long expiresAtNanos) {
            this.rules = rules;
            this.expiresAtNanos = expiresAtNanos;
        }
    }
}
