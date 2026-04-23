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
 * Action type for indexing Wazuh detectors.
 *
 * <p>This action is registered under the cluster admin namespace and provides the entry point for
 * detector write operations through the transport layer.
 *
 * <p>Action name: cluster:admin/wazuh/securityanalytics/detector/write
 *
 * @see WIndexDetectorRequest
 * @see WIndexDetectorResponse
 */
public class WIndexDetectorAction extends ActionType<WIndexDetectorResponse> {

    /** Singleton instance of this action. */
    public static final WIndexDetectorAction INSTANCE = new WIndexDetectorAction();

    /** The action name used for transport registration. */
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/detector/write";

    /** Private constructor to enforce singleton pattern. */
    public WIndexDetectorAction() {
        super(NAME, WIndexDetectorResponse::new);
    }
}
