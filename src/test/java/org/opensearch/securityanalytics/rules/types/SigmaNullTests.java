/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

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