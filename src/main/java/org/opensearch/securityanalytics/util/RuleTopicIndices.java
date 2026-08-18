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
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Objects;

public class RuleTopicIndices {
    private static final Logger log = LogManager.getLogger(RuleTopicIndices.class);

    private final Client client;

    private final ClusterService clusterService;
    private final LogTypeService logTypeService;

    public RuleTopicIndices(
            Client client, ClusterService clusterService, LogTypeService logTypeService) {
        this.client = client;
        this.clusterService = clusterService;
        this.logTypeService = logTypeService;
    }

    public static String ruleTopicIndexSettings() throws IOException {
        return new String(
                Objects.requireNonNull(
                                DetectorIndices.class
                                        .getClassLoader()
                                        .getResourceAsStream("mappings/detector-settings.json"))
                        .readAllBytes(),
                Charset.defaultCharset());
    }

    public void initRuleTopicIndexTemplate(ActionListener<AcknowledgedResponse> actionListener)
            throws IOException {
        getAllRuleIndices(
                ActionListener.wrap(
                        allRuleIndices -> {
                            // Compose list of all patterns to cover all query indices
                            ComposableIndexTemplate template =
                                    new ComposableIndexTemplate(
                                            allRuleIndices,
                                            new Template(
                                                    Settings.builder()
                                                            .loadFromSource(ruleTopicIndexSettings(), XContentType.JSON)
                                                            .build(),
                                                    null,
                                                    null),
                                            null,
                                            500L,
                                            null,
                                            null);
                            client.execute(
                                    PutComposableIndexTemplateAction.INSTANCE,
                                    new PutComposableIndexTemplateAction.Request(
                                                    DetectorMonitorConfig.OPENSEARCH_SAP_RULE_INDEX_TEMPLATE)
                                            .indexTemplate(template)
                                            .create(false),
                                    actionListener);
                        },
                        actionListener::onFailure));
    }

    public boolean ruleTopicIndexTemplateExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState
                        .metadata()
                        .templatesV2()
                        .get(DetectorMonitorConfig.OPENSEARCH_SAP_RULE_INDEX_TEMPLATE)
                != null;
    }

    private void getAllRuleIndices(ActionListener<List<String>> listener) {
        // A single wildcard pattern covers every per-log-type detector query index (including the
        // "-optimized-<uuid>-000001" variants and rollovers), so the template's analysis settings
        // (rule_analyzer / rule_ws_normalizer) apply regardless of log type.
        listener.onResponse(List.of(DetectorMonitorConfig.getRuleIndex("*") + "*"));
    }
}
