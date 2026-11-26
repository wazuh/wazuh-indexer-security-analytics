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
package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

/**
 * Action that rebuilds, once each, the detectors that reference any of a list of rules, so their
 * monitors run the rules' current compiled queries.
 *
 * @see WRefreshDetectorsRequest
 * @see WRefreshDetectorsResponse
 */
public class WRefreshDetectorsAction extends ActionType<WRefreshDetectorsResponse> {

    public static final WRefreshDetectorsAction INSTANCE = new WRefreshDetectorsAction();
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/detectors/refresh";

    public WRefreshDetectorsAction() {
        super(NAME, WRefreshDetectorsResponse::new);
    }
}
