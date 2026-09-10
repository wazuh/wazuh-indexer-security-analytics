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
