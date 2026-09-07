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
package org.opensearch.securityanalytics.rules.condition;

import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.objects.SigmaDetection;
import org.opensearch.securityanalytics.rules.objects.SigmaDetections;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.List;

public class ConditionIdentifier extends ConditionItem {

    private int argCount;
    private boolean tokenList;
    private String identifier;

    public ConditionIdentifier(
            List<
                            Either<
                                    AnyOneOf<
                                            ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>,
                                    String>>
                    args) {
        super(1, true, args);
        this.argCount = 1;
        this.tokenList = true;
        this.identifier = args.get(0).get();
    }

    @Override
    public ConditionItem postProcess(SigmaDetections detections, Object parent)
            throws SigmaConditionError {
        this.setParent((ConditionItem) parent);

        if (detections.getDetections().containsKey(this.identifier)) {
            SigmaDetection detection = detections.getDetections().get(this.identifier);
            AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression> item =
                    detection.postProcess(detections, this);
            return item.isLeft() ? item.getLeft() : (item.isMiddle() ? item.getMiddle() : item.get());
        } else {
            throw new SigmaConditionError(
                    "Detection '" + this.identifier + "' not defined in detections");
        }
    }
}
