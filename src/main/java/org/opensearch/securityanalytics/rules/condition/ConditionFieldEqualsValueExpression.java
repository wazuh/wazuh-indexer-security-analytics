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

import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.objects.SigmaDetections;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.Collections;

public class ConditionFieldEqualsValueExpression extends ConditionItem {

    private String field;
    private SigmaType value;

    private Either<ConditionItem, SigmaDetectionItem> parent;

    public ConditionFieldEqualsValueExpression(String field, SigmaType value) {
        super(2, false, Collections.emptyList());
        this.field = field;
        this.value = value;
    }

    @Override
    public ConditionFieldEqualsValueExpression postProcess(
            SigmaDetections detections, Object parent) {
        this.parent =
                parent instanceof ConditionItem
                        ? Either.left((ConditionItem) parent)
                        : Either.right((SigmaDetectionItem) parent);
        return this;
    }

    public String getField() {
        return field;
    }

    public SigmaType getValue() {
        return value;
    }
}
