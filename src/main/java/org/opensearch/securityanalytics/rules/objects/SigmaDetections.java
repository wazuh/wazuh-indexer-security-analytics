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
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaDetectionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SigmaDetections {

    private Map<String, SigmaDetection> detections;

    private List<String> condition;

    private String timeframe;

    private List<SigmaCondition> parsedCondition;

    public SigmaDetections(
            Map<String, SigmaDetection> detections, List<String> condition, String timeframe)
            throws SigmaDetectionError, SigmaConditionError {
        this.detections = detections;
        this.condition = condition;
        this.timeframe = timeframe;

        if (this.detections.isEmpty()) {
            throw new SigmaDetectionError("No detections defined in Sigma rule");
        }

        this.parsedCondition = new ArrayList<>();
        for (String cond : this.condition) {
            this.parsedCondition.add(new SigmaCondition(cond, this));
        }
    }

    @SuppressWarnings("unchecked")
    protected static SigmaDetections fromDict(Map<String, Object> detectionMap)
            throws SigmaConditionError,
                    SigmaDetectionError,
                    SigmaModifierError,
                    SigmaValueError,
                    SigmaRegularExpressionError {
        List<String> conditionList = new ArrayList<>();
        if (detectionMap.containsKey("condition") && detectionMap.get("condition") instanceof List) {
            conditionList.addAll((List<String>) detectionMap.get("condition"));
        } else if (detectionMap.containsKey("condition")) {
            conditionList.add(detectionMap.get("condition").toString());
        } else {
            throw new SigmaConditionError("Sigma rule must contain at least one condition");
        }

        Map<String, SigmaDetection> detections = new HashMap<>();
        for (Map.Entry<String, Object> detection : detectionMap.entrySet()) {
            if (!"condition".equals(detection.getKey())) {
                detections.put(detection.getKey(), SigmaDetection.fromDefinition(detection.getValue()));
            }
        }

        String timeframe = null;
        if (detectionMap.containsKey("timeframe")) {
            timeframe = detectionMap.get("timeframe").toString();
        }

        return new SigmaDetections(detections, conditionList, timeframe);
    }

    public Map<String, SigmaDetection> getDetections() {
        return detections;
    }

    public List<String> getCondition() {
        return condition;
    }

    public List<SigmaCondition> getParsedCondition() {
        return parsedCondition;
    }

    public String getTimeframe() {
        return timeframe;
    }
}
