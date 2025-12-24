package org.opensearch.securityanalytics.transport;

import com.wazuh.securityanalytics.action.WIndexRuleAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.CompositeSigmaErrors;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;
import static org.opensearch.securityanalytics.model.Rule.PRE_PACKAGED_RULES_INDEX;

public class WazuhTransportIndexRuleAction extends HandledTransportAction<WIndexRuleRequest, WIndexRuleResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(WazuhTransportIndexRuleAction.class);

    private final Client client;

    @Inject
    public WazuhTransportIndexRuleAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(WIndexRuleAction.NAME, transportService, actionFilters, WIndexRuleRequest::new);
        this.client = client;

    }

    @Override
    protected void doExecute(Task task, WIndexRuleRequest request, ActionListener<WIndexRuleResponse> listener) {
        try {
            Map<String, String> fieldMappings = Map.of(); // TODO: get field mappings for Wazuh log types
            QueryBackend backend = new OSQueryBackend(fieldMappings, true, true);
            Rule rule = this.getRule(backend, request.getLogType(), request.getRule());

            IndexRequest indexRequest = new IndexRequest(PRE_PACKAGED_RULES_INDEX)
                    .id(rule.getId())
                    .source(rule.toXContent(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                    .timeout(TimeValue.timeValueSeconds(10));
            client.index(indexRequest, new ActionListener<>() {
                @Override
                public void onResponse(org.opensearch.action.index.IndexResponse indexResponse) {
                    log.info("Successfully indexed rule with id: " + indexResponse.getId());
                    listener.onResponse(new WIndexRuleResponse(indexResponse.getId(), indexResponse.getVersion(), indexResponse.status()));
                }

                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                }
            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (SigmaError e) {
            throw new RuntimeException(e);
        }
    }

    private Rule getRule(QueryBackend backend, String category, String ruleStr) throws SigmaError, CompositeSigmaErrors {
        SigmaRule parsedRule = SigmaRule.fromYaml(ruleStr, true);
        backend.resetQueryFields();
        List<Object> ruleQueries = backend.convertRule(parsedRule);
        Set<String> queryFieldNames = backend.getQueryFields().keySet();

        Rule rule = new Rule(
                parsedRule.getId().toString(), NO_VERSION, parsedRule, category,
                ruleQueries.stream().map(Object::toString).collect(Collectors.toList()),
                new ArrayList<>(queryFieldNames),
                ruleStr
        );
        return rule;
    }
}
