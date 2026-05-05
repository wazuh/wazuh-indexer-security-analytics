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
package org.opensearch.securityanalytics.rules.modifiers;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.types.SigmaBool;
import org.opensearch.securityanalytics.rules.types.SigmaExists;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.List;

/**
 * Implements the Sigma "exists" modifier, which checks whether a field is present or absent in a
 * log event.
 *
 * <p>Usage in a Sigma rule:
 *
 * <pre>
 *   field|exists: true   # field must be present
 *   field|exists: false  # field must be absent
 * </pre>
 */
public class SigmaExistsModifier extends SigmaValueModifier {

    public SigmaExistsModifier(
            SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
    }

    @Override
    public Pair<Class<?>, Class<?>> getTypeHints() {
        return Pair.of(SigmaBool.class, null);
    }

    @Override
    public Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val)
            throws SigmaValueError {
        if (val.isLeft() && val.getLeft() instanceof SigmaBool) {
            boolean fieldExists = ((SigmaBool) val.getLeft()).isaBoolean();
            return Either.left(new SigmaExists(fieldExists));
        }
        throw new SigmaValueError("exists modifier requires a boolean value (true or false)");
    }
}
