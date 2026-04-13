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
package org.opensearch.securityanalytics.transport;

import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.test.OpenSearchTestCase;

import java.util.HashMap;
import java.util.Map;

public class TransportCorrelateFindingActionTests extends OpenSearchTestCase {

    public void testAddLogTypeIfValid_withValidSource_addsLogType() {
        Map<String, CustomLogType> logTypes = new HashMap<>();

        TransportCorrelateFindingAction.addLogTypeIfValid(
                logTypes, validSource("windows", "Windows logs"), "hit-1", "monitor-1", "finding-1");

        assertEquals(1, logTypes.size());
        assertTrue(logTypes.containsKey("windows"));
        assertEquals("Windows logs", logTypes.get("windows").getDescription());
    }

    public void testAddLogTypeIfValid_missingName_skipsSource() {
        Map<String, CustomLogType> logTypes = new HashMap<>();
        Map<String, Object> source = new HashMap<>();
        source.put("description", "Linux logs");
        source.put("space", "default");
        source.put("tags", Map.of("source", "linux"));

        TransportCorrelateFindingAction.addLogTypeIfValid(
                logTypes, source, "hit-missing-name", "monitor-1", "finding-1");

        assertTrue(logTypes.isEmpty());
    }

    public void testAddLogTypeIfValid_mixedSources_keepsOnlyValidEntries() {
        Map<String, CustomLogType> logTypes = new HashMap<>();

        Map<String, Object> missingNameSource = new HashMap<>();
        missingNameSource.put("description", "Missing name");
        missingNameSource.put("space", "default");
        missingNameSource.put("tags", Map.of("source", "broken"));

        Map<String, Object> missingDescriptionSource = new HashMap<>();
        missingDescriptionSource.put("name", "broken");
        missingDescriptionSource.put("space", "default");
        missingDescriptionSource.put("tags", Map.of("source", "broken"));

        TransportCorrelateFindingAction.addLogTypeIfValid(
                logTypes, validSource("apache", "Apache logs"), "hit-valid", "monitor-1", "finding-1");
        TransportCorrelateFindingAction.addLogTypeIfValid(
                logTypes, missingNameSource, "hit-missing-name", "monitor-1", "finding-1");
        TransportCorrelateFindingAction.addLogTypeIfValid(
                logTypes, missingDescriptionSource, "hit-missing-description", "monitor-1", "finding-1");

        assertEquals(1, logTypes.size());
        assertTrue(logTypes.containsKey("apache"));
    }

    private static Map<String, Object> validSource(String name, String description) {
        Map<String, Object> source = new HashMap<>();
        source.put("name", name);
        source.put("description", description);
        source.put("space", "default");
        source.put("category", "web");
        source.put("tags", Map.of("source", "wazuh"));
        return source;
    }
}
