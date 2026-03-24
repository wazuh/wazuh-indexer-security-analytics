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
package org.opensearch.securityanalytics.model;

import java.util.Arrays;
import java.util.Locale;

public enum LOG_CATEGORY {
    ACCESS_MANAGEMENT("Access Management"),
    APPLICATIONS("Applications"),
    CLOUD_SERVICES("Cloud Services"),
    NETWORK_ACTIVITY("Network Activity"),
    SECURITY("Security"),
    SYSTEM_ACTIVITY("System Activity"),
    OTHER("Other"),
    UNCLASSIFIED("Unclassified");

    private final String categoryName;

    LOG_CATEGORY(String categoryName) {
        this.categoryName = categoryName;
    }

    public String getCategoryName() {
        return this.categoryName;
    }

    public String getLowerCaseName() {
        return this.getCategoryName().trim().replace(" ", "-").toLowerCase(Locale.ROOT);
    }

    public static boolean isValidCategory(String categoryName) {
        return Arrays.stream(LOG_CATEGORY.values())
                .anyMatch(c -> c.name().equalsIgnoreCase(categoryName));
    }
}
