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

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/**
 * Single-entry TTL cache holding the parsed list of log types from {@code
 * LogTypeService.LOG_TYPE_INDEX}. The query is parameter-less and identical for every finding, so a
 * single in-memory snapshot can serve all callers between TTL refreshes.
 *
 * <p>A TTL of zero disables the cache.
 */
public final class LogTypeListCache {

    private final AtomicReference<Entry> snapshot = new AtomicReference<>();
    private final LongSupplier clock;
    private volatile long ttlNanos;

    public LogTypeListCache(TimeValue ttl) {
        this(ttl, System::nanoTime);
    }

    LogTypeListCache(TimeValue ttl, LongSupplier clock) {
        this.ttlNanos = ttl.nanos();
        this.clock = clock;
    }

    public Optional<Map<String, CustomLogType>> get() {
        if (ttlNanos <= 0) {
            return Optional.empty();
        }
        Entry entry = snapshot.get();
        if (entry == null) {
            return Optional.empty();
        }
        if (clock.getAsLong() > entry.expiresAtNanos) {
            snapshot.compareAndSet(entry, null);
            return Optional.empty();
        }
        return Optional.of(entry.logTypes);
    }

    public void put(Map<String, CustomLogType> logTypes) {
        long ttl = ttlNanos;
        if (ttl <= 0 || logTypes == null) {
            return;
        }
        snapshot.set(new Entry(logTypes, clock.getAsLong() + ttl));
    }

    public void invalidate() {
        snapshot.set(null);
    }

    public void setTtl(TimeValue ttl) {
        long newTtl = ttl.nanos();
        this.ttlNanos = newTtl;
        if (newTtl <= 0) {
            snapshot.set(null);
        }
    }

    boolean isCached() {
        return get().isPresent();
    }

    private static final class Entry {
        final Map<String, CustomLogType> logTypes;
        final long expiresAtNanos;

        Entry(Map<String, CustomLogType> logTypes, long expiresAtNanos) {
            this.logTypes = logTypes;
            this.expiresAtNanos = expiresAtNanos;
        }
    }
}
