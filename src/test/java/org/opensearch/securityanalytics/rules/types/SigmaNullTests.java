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

public class SigmaNullTests extends OpenSearchTestCase {

    public void testNullEqual() {
        SigmaNull n1 = new SigmaNull();
        SigmaNull n2 = new SigmaNull();
        Assert.assertEquals(n1, n2);
    }

    public void testNullNotEqualToNullReference() {
        // Called directly rather than through assertNotEquals, which short-circuits on null:
        // this is what used to throw a NullPointerException.
        Assert.assertFalse(new SigmaNull().equals(null));
    }

    public void testNullNotEqualToOtherType() {
        Assert.assertNotEquals(new SigmaNull(), "null");
    }

    public void testNullHashCodeConsistent() {
        Assert.assertEquals(new SigmaNull().hashCode(), new SigmaNull().hashCode());
    }
}
