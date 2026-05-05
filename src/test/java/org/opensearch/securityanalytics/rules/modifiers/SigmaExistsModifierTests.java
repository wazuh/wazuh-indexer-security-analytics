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
import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.types.SigmaBool;
import org.opensearch.securityanalytics.rules.types.SigmaExists;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.junit.Assert;

import java.util.Collections;
import java.util.List;

public class SigmaExistsModifierTests extends SigmaModifierTests {

    public void testExistsModifierWithTrueProducesSigmaExistsTrue()
            throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values =
                new SigmaExistsModifier(dummyDetectionItem(), Collections.emptyList())
                        .apply(Either.left(new SigmaBool(true)));

        Assert.assertEquals(1, values.size());
        Assert.assertTrue(values.get(0) instanceof SigmaExists);
        Assert.assertTrue(((SigmaExists) values.get(0)).exists());
    }

    public void testExistsModifierWithFalseProducesSigmaExistsFalse()
            throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values =
                new SigmaExistsModifier(dummyDetectionItem(), Collections.emptyList())
                        .apply(Either.left(new SigmaBool(false)));

        Assert.assertEquals(1, values.size());
        Assert.assertTrue(values.get(0) instanceof SigmaExists);
        Assert.assertFalse(((SigmaExists) values.get(0)).exists());
    }

    public void testExistsModifierTypeHintIsSigmaBool()
            throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaExistsModifier modifier =
                new SigmaExistsModifier(dummyDetectionItem(), Collections.emptyList());

        Pair<Class<?>, Class<?>> hints = modifier.getTypeHints();
        Assert.assertEquals(SigmaBool.class, hints.getLeft());
        Assert.assertNull(hints.getRight());
    }

    public void testExistsModifierTypeCheckAcceptsSigmaBool()
            throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaExistsModifier modifier =
                new SigmaExistsModifier(dummyDetectionItem(), Collections.emptyList());

        Assert.assertTrue(modifier.typeCheck(Either.left(new SigmaBool(true))));
        Assert.assertTrue(modifier.typeCheck(Either.left(new SigmaBool(false))));
    }

    public void testExistsModifierTypeCheckRejectsSigmaString()
            throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaExistsModifier modifier =
                new SigmaExistsModifier(dummyDetectionItem(), Collections.emptyList());

        Assert.assertFalse(modifier.typeCheck(Either.left(new SigmaString("true"))));
    }

    public void testExistsModifierTypeCheckRejectsSigmaNumber()
            throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaExistsModifier modifier =
                new SigmaExistsModifier(dummyDetectionItem(), Collections.emptyList());

        Assert.assertFalse(modifier.typeCheck(Either.left(new SigmaNumber(1))));
    }

    public void testExistsModifierApplyWithInvalidTypeThrowsSigmaTypeError()
            throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaExistsModifier modifier =
                new SigmaExistsModifier(dummyDetectionItem(), Collections.emptyList());

        assertThrows(SigmaTypeError.class, () -> modifier.apply(Either.left(new SigmaString("true"))));
    }

    public void testExistsModifierRegisteredInFacade() {
        Class<? extends SigmaModifier> modifierClass = SigmaModifierFacade.getModifier("exists");
        Assert.assertNotNull(modifierClass);
        Assert.assertEquals(SigmaExistsModifier.class, modifierClass);
    }
}
