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
 * Action that checks a Sigma rule the way storing it would (parse, WCS fields, compilation),
 * without storing anything.
 *
 * @see WValidateRuleRequest
 * @see WValidateRuleResponse
 */
public class WValidateRuleAction extends ActionType<WValidateRuleResponse> {

    public static final WValidateRuleAction INSTANCE = new WValidateRuleAction();
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/rule/validate";

    public WValidateRuleAction() {
        super(NAME, WValidateRuleResponse::new);
    }
}
