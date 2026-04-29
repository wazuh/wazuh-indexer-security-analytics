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
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

public class SigmaExistsTests extends OpenSearchTestCase {

    public void testExistsTrueReturnsTrue() {
        SigmaExists sigmaExists = new SigmaExists(true);
        Assert.assertTrue(sigmaExists.exists());
    }

    public void testExistsFalseReturnsFalse() {
        SigmaExists sigmaExists = new SigmaExists(false);
        Assert.assertFalse(sigmaExists.exists());
    }

    public void testExistsTrueToString() {
        SigmaExists sigmaExists = new SigmaExists(true);
        Assert.assertEquals("true", sigmaExists.toString());
    }

    public void testExistsFalseToString() {
        SigmaExists sigmaExists = new SigmaExists(false);
        Assert.assertEquals("false", sigmaExists.toString());
    }

    public void testExistsEqualsSameValue() {
        SigmaExists a = new SigmaExists(true);
        SigmaExists b = new SigmaExists(true);
        Assert.assertEquals(a, b);
    }

    public void testExistsNotEqualsDifferentValue() {
        SigmaExists a = new SigmaExists(true);
        SigmaExists b = new SigmaExists(false);
        Assert.assertNotEquals(a, b);
    }

    public void testExistsEqualsSelf() {
        SigmaExists sigmaExists = new SigmaExists(true);
        Assert.assertEquals(sigmaExists, sigmaExists);
    }

    public void testExistsNotEqualsNull() {
        SigmaExists sigmaExists = new SigmaExists(true);
        Assert.assertNotEquals(sigmaExists, null);
    }

    public void testExistsNotEqualsDifferentType() {
        SigmaExists sigmaExists = new SigmaExists(true);
        Assert.assertNotEquals(sigmaExists, "true");
    }

    public void testExistsHashCodeConsistentForTrue() {
        SigmaExists a = new SigmaExists(true);
        SigmaExists b = new SigmaExists(true);
        Assert.assertEquals(a.hashCode(), b.hashCode());
    }

    public void testExistsHashCodeDiffersForDifferentValues() {
        SigmaExists trueExists = new SigmaExists(true);
        SigmaExists falseExists = new SigmaExists(false);
        Assert.assertNotEquals(trueExists.hashCode(), falseExists.hashCode());
    }
}
