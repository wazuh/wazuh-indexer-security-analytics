/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wazuh.securityanalytics.action;

import org.opensearch.action.ActionType;

/**
 * Action type for indexing Wazuh rules.
 * <p>
 * This action is registered under the cluster admin namespace and provides
 * the entry point for rule write operations through the transport layer.
 * <p>
 * Action name: cluster:admin/wazuh/securityanalytics/rule/write
 *
 * @see WIndexRuleRequest
 * @see WIndexRuleResponse
 */
public class WIndexRuleAction extends ActionType<WIndexRuleResponse> {

    /** Singleton instance of this action. */
    public static final WIndexRuleAction INSTANCE = new WIndexRuleAction();

    /** The action name used for transport registration. */
    public static final String NAME = "cluster:admin/wazuh/securityanalytics/rule/write";

    /** Private constructor to enforce singleton pattern. */
    public WIndexRuleAction() {
        super(NAME, WIndexRuleResponse::new);
    }
}
