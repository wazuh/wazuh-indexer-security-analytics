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

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Covers the persistence of the upstream Sigma identifier, from the rule body through to the rule
 * document stored in the rules index.
 *
 * <p>The {@code sigma_id} field must survive parsing, serialization to XContent and parsing back,
 * because enriched findings read it from the stored rule document. It must also stay distinct from
 * the rule's own {@code id}: the two are different UUIDs and conflating them is the defect behind
 * <a href="https://github.com/wazuh/wazuh-indexer-security-analytics/issues/304">issue 304</a>.
 */
public class RuleSigmaIdTests extends OpenSearchTestCase {

    private static final String RULE_ID = "ed85157d-711b-4edb-8390-492ec63c92ac";
    private static final String SIGMA_ID = "1da8ce0b-855d-4004-8860-7d64d42063b1";

    private static String ruleYaml(String sigmaIdLine) {
        return "id: "
                + RULE_ID
                + "\n"
                + sigmaIdLine
                + "status: stable\n"
                + "level: high\n"
                + "logsource:\n"
                + "    product: apache-http\n"
                + "detection:\n"
                + "    selection:\n"
                + "        message|contains: exit signal Segmentation Fault\n"
                + "    condition: selection\n"
                + "falsepositives:\n"
                + "    - Unknown\n"
                + "metadata:\n"
                + "    title: Apache segmentation fault\n"
                + "    author: Wazuh, Inc.\n"
                + "    date: '2026-09-04'\n";
    }

    private static Rule ruleDoc(String yaml) {
        SigmaRule parsed = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(
                "rule must parse cleanly: " + parsed.getErrors().getErrors(),
                parsed.getErrors().getErrors().isEmpty());
        return new Rule(
                "rules-index-id",
                1L,
                parsed,
                "apache-http",
                Collections.emptyList(),
                Collections.emptyList(),
                yaml);
    }

    private static Rule roundTripXContent(Rule rule) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        rule.toXContent(builder, ToXContent.EMPTY_PARAMS);
        String json = builder.toString();

        XContentParser parser =
                XContentType.JSON
                        .xContent()
                        .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, json);
        parser.nextToken();
        return Rule.parse(parser, rule.getId(), rule.getVersion());
    }

    /** The upstream Sigma identifier is carried from the rule body onto the rule document. */
    public void testSigmaIdIsCarriedFromSigmaRule() {
        Rule rule = ruleDoc(ruleYaml("sigma_id: " + SIGMA_ID + "\n"));

        Assert.assertEquals(SIGMA_ID, rule.getSigmaId());
        Assert.assertNotEquals(
                "sigma_id must not be the rules-index id", rule.getId(), rule.getSigmaId());
    }

    /**
     * The identifier survives the XContent round trip, which is how the rules index stores the
     * document and how the finding-enrichment path reads it back.
     */
    public void testSigmaIdSurvivesXContentRoundTrip() throws IOException {
        Rule parsed = roundTripXContent(ruleDoc(ruleYaml("sigma_id: " + SIGMA_ID + "\n")));

        Assert.assertEquals(SIGMA_ID, parsed.getSigmaId());
    }

    /** The identifier survives transport serialization. */
    public void testSigmaIdSurvivesStreamRoundTrip() throws IOException {
        Rule rule = ruleDoc(ruleYaml("sigma_id: " + SIGMA_ID + "\n"));
        rule.setDocumentId("5db5e8e9-85f4-5cac-b97a-9eb39f16aa33");

        BytesStreamOutput out = new BytesStreamOutput();
        rule.writeTo(out);
        Rule read = Rule.readFrom(StreamInput.wrap(out.bytes().toBytesRef().bytes));

        Assert.assertEquals(SIGMA_ID, read.getSigmaId());
        Assert.assertEquals("5db5e8e9-85f4-5cac-b97a-9eb39f16aa33", read.getDocumentId());
    }

    /**
     * A rule that declares no upstream identifier stores none: the field is left out of the document
     * entirely rather than defaulted to another id.
     */
    public void testSigmaIdAbsentIsNotSerialized() throws IOException {
        Rule rule = ruleDoc(ruleYaml(""));
        Assert.assertNull(rule.getSigmaId());

        XContentBuilder builder = XContentFactory.jsonBuilder();
        rule.toXContent(builder, ToXContent.EMPTY_PARAMS);
        Assert.assertFalse(
                "sigma_id must not appear in the stored document", builder.toString().contains("sigma_id"));

        Assert.assertNull(roundTripXContent(rule).getSigmaId());
    }

    /**
     * The three identifiers a rule document carries are independent and none overwrites another: the
     * rules-index {@code _id}, the rule's own {@code document.id}, and the upstream {@code sigma_id}.
     */
    public void testSigmaIdDocumentIdAndRulesIndexIdAreIndependent() throws IOException {
        Rule rule = ruleDoc(ruleYaml("sigma_id: " + SIGMA_ID + "\n"));
        rule.setDocumentId("5db5e8e9-85f4-5cac-b97a-9eb39f16aa33");
        rule.setSpace("custom");

        Rule parsed = roundTripXContent(rule);

        List<String> ids = List.of(parsed.getId(), parsed.getDocumentId(), parsed.getSigmaId());
        Assert.assertEquals("all three identifiers must differ", 3, Set.copyOf(ids).size());
        Assert.assertEquals("rules-index-id", parsed.getId());
        Assert.assertEquals("5db5e8e9-85f4-5cac-b97a-9eb39f16aa33", parsed.getDocumentId());
        Assert.assertEquals(SIGMA_ID, parsed.getSigmaId());
    }
}
