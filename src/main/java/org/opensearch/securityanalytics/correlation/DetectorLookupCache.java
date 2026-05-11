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

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * In-memory cache of {@code monitorId -> Detector} with a TTL. Backed by a {@link
 * ConcurrentHashMap}; expired entries are evicted lazily on read.
 *
 * <p>Sized implicitly by the number of distinct detectors in the cluster, so no LRU bound is
 * applied. A TTL of zero disables the cache (every {@link #get(String)} returns empty and {@link
 * #put(String, Detector)} is a no-op).
 */
public final class DetectorLookupCache {

    private final ConcurrentHashMap<String, Entry> byMonitorId = new ConcurrentHashMap<>();
    private final LongSupplier clock;
    private volatile long ttlNanos;

    public DetectorLookupCache(TimeValue ttl) {
        this(ttl, System::nanoTime);
    }

    DetectorLookupCache(TimeValue ttl, LongSupplier clock) {
        this.ttlNanos = ttl.nanos();
        this.clock = clock;
    }

    public Optional<Detector> get(String monitorId) {
        if (ttlNanos <= 0) {
            return Optional.empty();
        }
        Entry entry = byMonitorId.get(monitorId);
        if (entry == null) {
            return Optional.empty();
        }
        if (clock.getAsLong() > entry.expiresAtNanos) {
            byMonitorId.remove(monitorId, entry);
            return Optional.empty();
        }
        return Optional.of(entry.detector);
    }

    public void put(String monitorId, Detector detector) {
        long ttl = ttlNanos;
        if (ttl <= 0 || detector == null) {
            return;
        }
        byMonitorId.put(monitorId, new Entry(detector, clock.getAsLong() + ttl));
    }

    public void invalidate(String monitorId) {
        byMonitorId.remove(monitorId);
    }

    public void invalidateAll() {
        byMonitorId.clear();
    }

    public void setTtl(TimeValue ttl) {
        long newTtl = ttl.nanos();
        this.ttlNanos = newTtl;
        if (newTtl <= 0) {
            byMonitorId.clear();
        }
    }

    int size() {
        return byMonitorId.size();
    }

    private static final class Entry {
        final Detector detector;
        final long expiresAtNanos;

        Entry(Detector detector, long expiresAtNanos) {
            this.detector = detector;
            this.expiresAtNanos = expiresAtNanos;
        }
    }
}
