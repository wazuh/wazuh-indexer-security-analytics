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
package org.opensearch.securityanalytics.model;

import org.opensearch.action.support.clustermanager.AcknowledgedResponse;

import java.util.Map;

public class CreateMappingResult {

    private AcknowledgedResponse acknowledgedResponse;
    private String concreteIndexName;
    private Map<String, Object> mappings;

    public CreateMappingResult() {}

    public CreateMappingResult(
            AcknowledgedResponse acknowledgedResponse,
            String concreteIndexName,
            Map<String, Object> mappingsSource) {
        this.acknowledgedResponse = acknowledgedResponse;
        this.concreteIndexName = concreteIndexName;
        this.mappings = mappingsSource;
    }

    public AcknowledgedResponse getAcknowledgedResponse() {
        return acknowledgedResponse;
    }

    public void setAcknowledgedResponse(AcknowledgedResponse acknowledgedResponse) {
        this.acknowledgedResponse = acknowledgedResponse;
    }

    public String getConcreteIndexName() {
        return concreteIndexName;
    }

    public void setConcreteIndexName(String concreteIndexName) {
        this.concreteIndexName = concreteIndexName;
    }

    public Map<String, Object> getMappings() {
        return mappings;
    }

    public void setMappings(Map<String, Object> mappings) {
        this.mappings = mappings;
    }
}
