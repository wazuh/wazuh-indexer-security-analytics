/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

public class SigmaTypeFacade {

    public static SigmaType sigmaType(Object val) {
        if (val == null) {
            return new SigmaNull();
        } else if (val.getClass().equals(Boolean.class)) {
            return new SigmaBool((Boolean) val);
        } else if (val.getClass().equals(Integer.class)) {
            return new SigmaNumber((Integer) val);
        } else if (val.getClass().equals(Float.class)) {
            return new SigmaNumber((Float) val);
        } else if (val.getClass().equals(String.class)) {
            return new SigmaString((String) val);
        } else {
            return new SigmaNull();
        }
    }
}