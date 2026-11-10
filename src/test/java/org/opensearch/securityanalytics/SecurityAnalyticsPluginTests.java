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
package org.opensearch.securityanalytics;

import org.opensearch.securityanalytics.enrichment.WazuhEnrichedFindingService;
import org.opensearch.test.OpenSearchTestCase;

import java.lang.reflect.Field;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class SecurityAnalyticsPluginTests extends OpenSearchTestCase {

    /**
     * The node closes plugins, not the components they create, so the plugin has to close the
     * enrichment service itself for the findings it still holds at shutdown to be reported.
     */
    public void testClose_closesTheEnrichmentService() throws Exception {
        SecurityAnalyticsPlugin plugin = new SecurityAnalyticsPlugin();
        WazuhEnrichedFindingService service = mock(WazuhEnrichedFindingService.class);
        Field field = SecurityAnalyticsPlugin.class.getDeclaredField("enrichedFindingService");
        field.setAccessible(true);
        field.set(plugin, service);

        plugin.close();

        verify(service).close();
    }

    /** A plugin whose components were never created closes without failing. */
    public void testClose_withoutComponents_doesNothing() throws Exception {
        new SecurityAnalyticsPlugin().close();
    }
}
