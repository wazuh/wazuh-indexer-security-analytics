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
package org.opensearch.securityanalytics.indexmanagment;

import org.opensearch.Version;
import org.opensearch.action.admin.indices.rollover.RolloverInfo;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.test.OpenSearchTestCase;

import java.util.List;

/**
 * Unit tests for what the history retention sweep and the query index generation sweep pick for
 * deletion.
 */
public class DetectorIndexManagementServiceTests extends OpenSearchTestCase {

    private static final long NOW = 1_800_000_000_000L;
    private static final long DAY = 24L * 60 * 60 * 1000;
    private static final long RETENTION = 60 * DAY;
    private static final long GRACE =
            DetectorIndexManagementService.QUERY_INDEX_GENERATION_GRACE_PERIOD.millis();

    private static final String LOG_TYPE = "windows-rules";
    private static final String ALERTS_WRITE_ALIAS =
            DetectorMonitorConfig.getAlertsHistoryIndex(LOG_TYPE);
    private static final String QUERY_ALIAS =
            ".opensearch-sap-windows-rules-detectors-queries-optimized-03c2bbe0-108a-4919-9231-f3fffc28938c";

    /**
     * The active alerts index has no write alias, so a pattern matching it would delete it once it is
     * older than the retention period, and with it every alert a detector still holds.
     */
    public void testAlertSweepNeverPicksTheActiveAlertsIndex() {
        IndexMetadata active = index(".opensearch-sap-windows-rules-alerts", NOW - 2 * RETENTION);

        assertEquals(List.of(), selectAlertHistory(List.of(active), true));
        assertEquals(List.of(), selectAlertHistory(List.of(active), false));
    }

    /** A history index past the retention period is deleted. */
    public void testAlertSweepPicksAnOldHistoryIndex() {
        IndexMetadata old =
                index(".opensearch-sap-windows-rules-alerts-history-2026.09.01-1", NOW - RETENTION - DAY);

        assertEquals(
                List.of(".opensearch-sap-windows-rules-alerts-history-2026.09.01-1"),
                selectAlertHistory(List.of(old), true));
    }

    /** A history index within the retention period is kept. */
    public void testAlertSweepKeepsARecentHistoryIndex() {
        IndexMetadata recent =
                index(".opensearch-sap-windows-rules-alerts-history-2026.11.20-1", NOW - DAY);

        assertEquals(List.of(), selectAlertHistory(List.of(recent), true));
    }

    /** The index behind the write alias is still written to while history is enabled. */
    public void testAlertSweepKeepsTheWriteIndexWhileHistoryIsEnabled() {
        IndexMetadata write =
                withAlias(
                        ".opensearch-sap-windows-rules-alerts-history-2026.09.01-1",
                        NOW - RETENTION - DAY,
                        ALERTS_WRITE_ALIAS);

        assertEquals(List.of(), selectAlertHistory(List.of(write), true));
    }

    /** With history disabled, an old write index is deleted like any other. */
    public void testAlertSweepPicksTheWriteIndexWhenHistoryIsDisabled() {
        IndexMetadata write =
                withAlias(
                        ".opensearch-sap-windows-rules-alerts-history-2026.09.01-1",
                        NOW - RETENTION - DAY,
                        ALERTS_WRITE_ALIAS);

        assertEquals(
                List.of(".opensearch-sap-windows-rules-alerts-history-2026.09.01-1"),
                selectAlertHistory(List.of(write), false));
    }

    /**
     * History is found by name, not through the log types, which the sweep used to list with a cap of
     * 100 names and which no longer include a removed log type.
     */
    public void testAlertSweepPicksTheHistoryOfAnyLogType() {
        IndexMetadata removed =
                index(".opensearch-sap-removed-type-alerts-history-2026.09.01-1", NOW - RETENTION - DAY);

        assertEquals(
                List.of(".opensearch-sap-removed-type-alerts-history-2026.09.01-1"),
                selectAlertHistory(List.of(removed), false));
    }

    /**
     * Each kind of history is judged against its own write aliases only. The sweep used to judge
     * every index against every kind, so the alert history write index, which has no finding write
     * alias, was deleted by the finding check even with alert history enabled.
     */
    public void testFindingSweepDoesNotPickAlertHistory() {
        IndexMetadata alertWrite =
                withAlias(
                        ".opensearch-sap-windows-rules-alerts-history-2026.09.01-1",
                        NOW - RETENTION - DAY,
                        ALERTS_WRITE_ALIAS);

        assertEquals(List.of(), selectFindingHistory(List.of(alertWrite), false));
    }

    /** An old finding history index is deleted, the finding write index kept while enabled. */
    public void testFindingSweepPicksOldFindingHistory() {
        IndexMetadata old =
                index(".opensearch-sap-windows-rules-findings-2026.09.01-1", NOW - RETENTION - DAY);
        IndexMetadata write =
                withAlias(
                        ".opensearch-sap-windows-rules-findings-2026.09.02-000002",
                        NOW - RETENTION - DAY,
                        DetectorMonitorConfig.getFindingsIndex(LOG_TYPE));

        assertEquals(
                List.of(".opensearch-sap-windows-rules-findings-2026.09.01-1"),
                selectFindingHistory(List.of(old, write), true));
    }

    /**
     * The name must end like a rolled-over history index. A log type whose own name looks like
     * history must not lose its active alerts index.
     */
    public void testSweepsDoNotPickAnActiveAlertsIndexWithAHistoryLikeName() {
        IndexMetadata lookalike =
                index(".opensearch-sap-x-findings-2026.09.01-1-alerts", NOW - RETENTION - DAY);
        IndexMetadata lookalike2 =
                index(".opensearch-sap-x-alerts-history-2026.09.01-1-alerts", NOW - RETENTION - DAY);

        assertEquals(List.of(), selectFindingHistory(List.of(lookalike, lookalike2), false));
        assertEquals(List.of(), selectAlertHistory(List.of(lookalike, lookalike2), false));
    }

    /** Correlation history keeps its write index whatever its age. */
    public void testCorrelationSweepKeepsTheWriteIndex() {
        IndexMetadata write =
                withAlias(
                        ".opensearch-sap-correlation-history-2026.09.02-000002",
                        NOW - RETENTION - DAY,
                        ".opensearch-sap-correlation-history-write");
        IndexMetadata old =
                index(".opensearch-sap-correlation-history-2026.09.01-1", NOW - RETENTION - DAY);
        IndexMetadata others = index(".opensearch-sap-correlation-alerts", NOW - RETENTION - DAY);

        assertEquals(
                List.of(".opensearch-sap-correlation-history-2026.09.01-1"),
                DetectorIndexManagementService.selectExpiredHistoryIndices(
                        List.of(write, old, others),
                        DetectorIndexManagementService.CORRELATION_HISTORY_INDEX,
                        NOW,
                        RETENTION,
                        DetectorIndexManagementService.CORRELATION_HISTORY_WRITE_ALIAS,
                        true));
    }

    /** A generation left without an alias by a rollover more than the grace period ago is unused. */
    public void testPicksAGenerationRolledOverBeforeTheGracePeriod() {
        IndexMetadata previous = rolledOver(QUERY_ALIAS + "-000001", NOW - 10 * DAY, NOW - GRACE - 1);

        assertEquals(List.of(QUERY_ALIAS + "-000001"), selectUnusedGenerations(List.of(previous)));
    }

    /**
     * The run that rolled the index over may still percolate against the previous generation, so the
     * grace period counts from the rollover, not from the index creation.
     */
    public void testKeepsAGenerationRolledOverWithinTheGracePeriod() {
        IndexMetadata previous = rolledOver(QUERY_ALIAS + "-000001", NOW - 10 * DAY, NOW - GRACE / 2);

        assertEquals(List.of(), selectUnusedGenerations(List.of(previous)));
    }

    /** The generation behind the alias is the one the detector reads. */
    public void testKeepsTheGenerationBehindTheAlias() {
        IndexMetadata current = withAlias(QUERY_ALIAS + "-000002", NOW - 10 * DAY, QUERY_ALIAS);

        assertEquals(List.of(), selectUnusedGenerations(List.of(current)));
    }

    /** The chained-findings query index of a detector rolls over the same way. */
    public void testPicksAnUnusedChainedFindingsGeneration() {
        IndexMetadata previous =
                rolledOver(QUERY_ALIAS + "_chained_findings-000001", NOW - 10 * DAY, NOW - GRACE - 1);

        assertEquals(
                List.of(QUERY_ALIAS + "_chained_findings-000001"),
                selectUnusedGenerations(List.of(previous)));
    }

    /** Without a recorded rollover, the grace period counts from the index creation. */
    public void testPicksAnOldGenerationWithoutRolloverInfo() {
        IndexMetadata orphan = index(QUERY_ALIAS + "-000001", NOW - GRACE - 1);

        assertEquals(List.of(QUERY_ALIAS + "-000001"), selectUnusedGenerations(List.of(orphan)));
    }

    /**
     * A query index shared by several detectors keeps being read through an old generation by the
     * monitors whose metadata still points at it, so only dedicated query indices are swept.
     */
    public void testKeepsSharedQueryIndexGenerations() {
        IndexMetadata shared =
                rolledOver(
                        ".opensearch-sap-windows-rules-detectors-queries-000001",
                        NOW - 10 * DAY,
                        NOW - 10 * DAY);

        assertEquals(List.of(), selectUnusedGenerations(List.of(shared)));
    }

    /** The logtest index has no alias, but it is not a query index generation. */
    public void testKeepsTheLogtestIndex() {
        IndexMetadata logtest =
                index(".opensearch-sap-windows-rules-detectors-queries-logtest", NOW - 10 * DAY);

        assertEquals(List.of(), selectUnusedGenerations(List.of(logtest)));
    }

    private static List<String> selectAlertHistory(List<IndexMetadata> indices, boolean enabled) {
        return DetectorIndexManagementService.selectExpiredHistoryIndices(
                indices,
                DetectorIndexManagementService.ALERT_HISTORY_INDEX,
                NOW,
                RETENTION,
                DetectorIndexManagementService.ALERT_HISTORY_WRITE_ALIAS,
                enabled);
    }

    private static List<String> selectFindingHistory(List<IndexMetadata> indices, boolean enabled) {
        return DetectorIndexManagementService.selectExpiredHistoryIndices(
                indices,
                DetectorIndexManagementService.FINDING_HISTORY_INDEX,
                NOW,
                RETENTION,
                DetectorIndexManagementService.FINDING_HISTORY_WRITE_ALIAS,
                enabled);
    }

    private static List<String> selectUnusedGenerations(List<IndexMetadata> indices) {
        return DetectorIndexManagementService.selectUnusedQueryIndexGenerations(indices, NOW, GRACE);
    }

    private static IndexMetadata index(String name, long createdAt) {
        return builder(name, createdAt).build();
    }

    private static IndexMetadata withAlias(String name, long createdAt, String alias) {
        return builder(name, createdAt).putAlias(AliasMetadata.builder(alias)).build();
    }

    private static IndexMetadata rolledOver(String name, long createdAt, long rolledOverAt) {
        return builder(name, createdAt)
                .putRolloverInfo(new RolloverInfo(QUERY_ALIAS, List.of(), rolledOverAt))
                .build();
    }

    private static IndexMetadata.Builder builder(String name, long createdAt) {
        return IndexMetadata.builder(name)
                .settings(settings(Version.CURRENT))
                .numberOfShards(1)
                .numberOfReplicas(0)
                .creationDate(createdAt);
    }
}
