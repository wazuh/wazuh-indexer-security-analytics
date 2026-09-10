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

public class SigmaNumberTests extends OpenSearchTestCase {

    public void testNumberInt() {
        SigmaNumber n = new SigmaNumber(123);
        Assert.assertEquals("123", n.toString());
    }

    public void testNumberFloat() {
        SigmaNumber n = new SigmaNumber(12.34f);
        Assert.assertEquals("12.34", n.toString());
    }

    public void testNumberEqual() {
        SigmaNumber n1 = new SigmaNumber(123);
        SigmaNumber n2 = new SigmaNumber(123);
        Assert.assertEquals(n1, n2);
    }

    public void testNumberNotEqualForDifferentValues() {
        Assert.assertNotEquals(new SigmaNumber(1), new SigmaNumber(999));
    }

    public void testNumberNotEqualForIntAndFloat() {
        Assert.assertNotEquals(new SigmaNumber(1), new SigmaNumber(1.0f));
    }

    public void testNumberHashCodeConsistentForSameValue() {
        Assert.assertEquals(new SigmaNumber(123).hashCode(), new SigmaNumber(123).hashCode());
    }

    public void testNumberHashCodeDiffersForDifferentValues() {
        Assert.assertNotEquals(new SigmaNumber(1).hashCode(), new SigmaNumber(999).hashCode());
    }
}
