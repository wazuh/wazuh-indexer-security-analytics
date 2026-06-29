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
package org.opensearch.securityanalytics.settings;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.unit.TimeValue;

import java.util.concurrent.TimeUnit;

public class SecurityAnalyticsSettings {
    public static final String CORRELATION_INDEX = "index.correlation";
    public static final int minSystemIndexReplicas = 0;
    public static final int maxSystemIndexReplicas = 20;

    public static Setting<TimeValue> INDEX_TIMEOUT =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.index_timeout",
                    TimeValue.timeValueSeconds(60),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Long DEFAULT_MAX_ACTIONABLE_ALERT_COUNT = 50L;

    public static final Setting<Boolean> ALERT_HISTORY_ENABLED =
            Setting.boolSetting(
                    "plugins.security_analytics.alert_history_enabled",
                    false,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<Boolean> FINDING_HISTORY_ENABLED =
            Setting.boolSetting(
                    "plugins.security_analytics.alert_finding_enabled",
                    false,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<TimeValue> ALERT_HISTORY_ROLLOVER_PERIOD =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.alert_history_rollover_period",
                    TimeValue.timeValueHours(12),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<TimeValue> FINDING_HISTORY_ROLLOVER_PERIOD =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.alert_finding_rollover_period",
                    TimeValue.timeValueHours(12),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<TimeValue> CORRELATION_HISTORY_ROLLOVER_PERIOD =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.correlation_history_rollover_period",
                    TimeValue.timeValueHours(12),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<TimeValue> ALERT_HISTORY_INDEX_MAX_AGE =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.alert_history_max_age",
                    new TimeValue(30, TimeUnit.DAYS),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<TimeValue> FINDING_HISTORY_INDEX_MAX_AGE =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.finding_history_max_age",
                    new TimeValue(30, TimeUnit.DAYS),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<TimeValue> CORRELATION_HISTORY_INDEX_MAX_AGE =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.correlation_history_max_age",
                    new TimeValue(30, TimeUnit.DAYS),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<Long> ALERT_HISTORY_MAX_DOCS =
            Setting.longSetting(
                    "plugins.security_analytics.alert_history_max_docs",
                    1000L,
                    0L,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<Long> FINDING_HISTORY_MAX_DOCS =
            Setting.longSetting(
                    "plugins.security_analytics.alert_finding_max_docs",
                    1000L,
                    0L,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic,
                    Setting.Property.Deprecated);

    public static final Setting<Long> CORRELATION_HISTORY_MAX_DOCS =
            Setting.longSetting(
                    "plugins.security_analytics.correlation_history_max_docs",
                    1000L,
                    0L,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<TimeValue> ALERT_HISTORY_RETENTION_PERIOD =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.alert_history_retention_period",
                    new TimeValue(60, TimeUnit.DAYS),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<TimeValue> FINDING_HISTORY_RETENTION_PERIOD =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.finding_history_retention_period",
                    new TimeValue(60, TimeUnit.DAYS),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<TimeValue> CORRELATION_HISTORY_RETENTION_PERIOD =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.correlation_history_retention_period",
                    new TimeValue(60, TimeUnit.DAYS),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<Boolean> FILTER_BY_BACKEND_ROLES =
            Setting.boolSetting(
                    "plugins.security_analytics.filter_by_backend_roles",
                    false,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<Boolean> ENABLE_WORKFLOW_USAGE =
            Setting.boolSetting(
                    "plugins.security_analytics.enable_workflow_usage",
                    true,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<Boolean> IS_CORRELATION_INDEX_SETTING =
            Setting.boolSetting(CORRELATION_INDEX, false, Setting.Property.IndexScope);

    public static final Setting<TimeValue> CORRELATION_TIME_WINDOW =
            Setting.positiveTimeSetting(
                    "plugins.security_analytics.correlation_time_window",
                    new TimeValue(5, TimeUnit.MINUTES),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /** Setting which enables auto correlations */
    public static final Setting<Boolean> ENABLE_AUTO_CORRELATIONS =
            Setting.boolSetting(
                    "plugins.security_analytics.auto_correlations_enabled",
                    false,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<String> DEFAULT_MAPPING_SCHEMA =
            Setting.simpleString(
                    "plugins.security_analytics.mappings.default_schema",
                    "ecs",
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<Boolean> ENABLE_DETECTORS_WITH_DEDICATED_QUERY_INDICES =
            Setting.boolSetting(
                    "plugins.security_analytics.enable_detectors_with_dedicated_query_indices",
                    true,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    public static final Setting<Boolean> ENRICHED_FINDINGS_ENABLED =
            Setting.boolSetting(
                    "plugins.security_analytics.enriched_findings_index_enabled",
                    true,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of rule-metadata entries cached in memory by {@code
     * WazuhEnrichedFindingService}. Bounds heap growth: each entry holds a full rule document
     * (including compliance and MITRE maps). Least-recently-used entries are evicted past this size
     * and re-fetched on demand.
     */
    public static final Setting<Integer> ENRICHED_FINDINGS_RULE_CACHE_MAX_SIZE =
            Setting.intSetting(
                    "plugins.security_analytics.enriched_findings_rule_cache_max_size",
                    10000,
                    0,
                    Setting.Property.NodeScope);

    private static final int MAXIMUM_MAX_RULES_PER_DETECTOR = 50;
    public static final int DEFAULT_MAX_RULES_PER_DETECTOR = MAXIMUM_MAX_RULES_PER_DETECTOR;
    private static final int MINIMUM_MAX_RULES_PER_DETECTOR = 0;

    /**
     * Maximum number of rules allowed per detector input. Requests that would exceed this limit are
     * rejected with a 400 error.
     */
    public static final Setting<Integer> MAX_RULES_PER_DETECTOR =
            Setting.intSetting(
                    "plugins.security_analytics.max_rules_per_detector",
                    DEFAULT_MAX_RULES_PER_DETECTOR,
                    MINIMUM_MAX_RULES_PER_DETECTOR,
                    MAXIMUM_MAX_RULES_PER_DETECTOR,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    private static final int MAXIMUM_MAX_DETECTORS = 10;
    public static final int DEFAULT_MAX_DETECTORS = MAXIMUM_MAX_DETECTORS;
    private static final int MINIMUM_MAX_DETECTORS = 0;

    /**
     * Maximum number of user-created threat detectors allowed. Standard detectors created by the
     * Content Manager plugin are not counted towards this limit.
     */
    public static final Setting<Integer> MAX_DETECTORS =
            Setting.intSetting(
                    "plugins.security_analytics.max_detectors",
                    DEFAULT_MAX_DETECTORS,
                    MINIMUM_MAX_DETECTORS,
                    MAXIMUM_MAX_DETECTORS,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * TTL for the in-memory monitor-id to detector cache consulted by {@code
     * TransportCorrelateFindingAction}. Eliminates the per-finding nested-query lookup against the
     * detectors index when many findings of one fan-out share the same monitor id. Set to zero to
     * disable the cache entirely.
     */
    public static final Setting<TimeValue> CORRELATION_DETECTOR_CACHE_TTL =
            Setting.timeSetting(
                    "plugins.security_analytics.correlation.detector_cache_ttl",
                    TimeValue.timeValueMinutes(5),
                    TimeValue.timeValueSeconds(0),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of correlation pipelines allowed to run concurrently in {@code
     * TransportCorrelateFindingAction}. Bounds peak demand on the search thread pool when doc-level
     * alerting fan-outs publish many findings at once; excess findings queue until a slot frees up.
     */
    public static final Setting<Integer> CORRELATION_MAX_IN_FLIGHT_FINDINGS =
            Setting.intSetting(
                    "plugins.security_analytics.correlation.max_in_flight_findings",
                    50,
                    1,
                    1000,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * TTL for the in-memory caches of slow-changing correlation metadata (log type list and
     * correlation rules by detector type). Each cached lookup eliminates a per-finding {@code size:
     * 10000} search against the corresponding system index. Set to zero to disable both caches.
     */
    public static final Setting<TimeValue> CORRELATION_METADATA_CACHE_TTL =
            Setting.timeSetting(
                    "plugins.security_analytics.correlation.metadata_cache_ttl",
                    TimeValue.timeValueMinutes(5),
                    TimeValue.timeValueSeconds(0),
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);
}
