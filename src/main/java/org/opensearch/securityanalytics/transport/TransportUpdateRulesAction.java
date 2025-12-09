/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.transport;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wazuh.common.action.UpdateRulesRequest;
import com.wazuh.common.action.UpdateRulesAction;
import com.wazuh.common.action.UpdateRulesResponse;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Response;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.action.*;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class TransportUpdateRulesAction extends HandledTransportAction<ActionRequest, UpdateRulesResponse> {

    private final Client client;
    @Inject
    public TransportUpdateRulesAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client
    ) {
        super(UpdateRulesAction.NAME, transportService, actionFilters, UpdateRulesRequest::new);
        this.client = client;
    }

  @Override
  protected void doExecute(Task task, ActionRequest request,
      ActionListener<UpdateRulesResponse> actionListener) {
      BytesStreamOutput out = new BytesStreamOutput();
      try {
          request.writeTo((StreamOutput) out);
      } catch (IOException e) {
          throw new RuntimeException(e);
      }
      logger.info("Command Received from ContentManager plugin");

      logger.info("UpdateRulesRequest: {}", out.bytes().utf8ToString());
      try {
//          String jsonString = new String(out.bytes().utf8ToString().getBytes(), StandardCharsets.UTF_8);
          ObjectMapper mapper = new ObjectMapper();
          String jsonString = mapper.writeValueAsString(updateRulesRequest); // updateRulesRequest is your object
          JsonNode jsonNode = mapper.readTree(jsonString);


          logger.info("Parsed JSON Node: {}", jsonNode.toString());
          IndexRuleRequest ruleRequest = new IndexRuleRequest(jsonNode.get("ruleId").toString(), null,jsonNode.get("logType").toString(), null, jsonNode.get("rule").toString(), false);
          client.execute(IndexRuleAction.INSTANCE, ruleRequest, new ActionListener<IndexRuleResponse>() {
              @Override
              public void onResponse(IndexRuleResponse indexRuleResponse) {
                  logger.info("IndexRuleAction response received");
                  actionListener.onResponse(null);
              }

              @Override
              public void onFailure(Exception e) {
                  logger.error("IndexRuleAction failed: {}", e.getMessage());
                  actionListener.onFailure(e);
              }
          });
      } catch (JsonProcessingException e) {
          throw new RuntimeException(e);
      } catch (IOException e) {
          throw new RuntimeException(e);
      }
//              GetAllRuleCategoriesAction.INSTANCE,
//              new GetAllRuleCategoriesRequest(),
//              new ActionListener<>(){
//                  @Override
//                  public void onResponse(GetAllRuleCategoriesResponse getAllRuleCategoriesResponse) {
//                      try {
//                          XContentBuilder builder = XContentFactory.jsonBuilder();
//                            getAllRuleCategoriesResponse.toXContent(builder, null);
//                            logger.info("Received GetAllRuleCategoriesResponse with categories: {}", builder.toString());
//                      } catch (IOException e) {
//                          throw new RuntimeException(e);
//                      }
//                  }
//
//                  @Override
//                  public void onFailure(Exception e) {
//                      logger.info("Failed to internal request: {}", e.getMessage());
//                  }});
  }
}


//public class TransportUpdateRulesAction extends HandledTransportAction<UpdateRulesRequest, UpdateRulesResponse>  {
//
//    @Inject
//    public TransportUpdateRulesAction(
//            TransportService transportService,
//            ActionFilters actionFilters
//    ) {
//        super(UpdateRulesAction.NAME, transportService, actionFilters, UpdateRulesRequest::new);
//    }
//
//    @Override
//    public void doExecute(Task task, UpdateRulesRequest request, ActionListener<UpdateRulesResponse> listener) {
//        logger.info("Command Received from ContentManager plugin");
//        logger.info("UpdateRulesRequest: {}", request.getJsonBody());
//
//    }
//}