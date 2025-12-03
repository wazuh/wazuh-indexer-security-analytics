/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.transport;

import com.wazuh.common.action.UpdateRulesRequest;
import com.wazuh.common.action.UpdateRulesAction;
import com.wazuh.common.action.UpdateRulesResponse;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportUpdateRulesAction extends HandledTransportAction<ActionRequest, UpdateRulesResponse> {

  @Inject
  public TransportUpdateRulesAction(
      TransportService transportService,
      ActionFilters actionFilters
      ) {
    super(UpdateRulesAction.NAME, transportService, actionFilters, UpdateRulesRequest::new);
  }

  @Override
  protected void doExecute(Task task, ActionRequest request,
      ActionListener<UpdateRulesResponse> actionListener) {
      logger.info("Command Received from ContentManager plugin");
  }
}
