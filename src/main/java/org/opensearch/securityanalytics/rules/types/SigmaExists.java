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

/**
 * Represents the result of the Sigma "exists" modifier, which checks whether a field is present
 * (exists=true) or absent (exists=false) in a log event.
 */
public class SigmaExists implements SigmaType {

    private final boolean exists;

    public SigmaExists(boolean exists) {
        this.exists = exists;
    }

    public boolean exists() {
        return exists;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SigmaExists that = (SigmaExists) o;
        return exists == that.exists;
    }

    @Override
    public int hashCode() {
        return Boolean.hashCode(exists);
    }

    @Override
    public String toString() {
        return String.valueOf(exists);
    }
}
