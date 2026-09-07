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
package org.opensearch.securityanalytics.action;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * {@code writeTo} and the {@code StreamInput} constructor of this request are written by hand and
 * had drifted apart: the constructor read a method the writer never wrote, so any cross-node hop
 * misread the stream from the field after it onwards. This pins them to each other for the shape
 * the REST layer now sends, and covers the name check the transport action took over from
 * {@code validate()}.
 */
public class IndexCorrelationRuleRequestTests extends OpenSearchTestCase {

    /**
     * The shape the REST layer now sends: the rule is absent and the client's bytes travel in its
     * place, for {@code TransportIndexCorrelationRuleAction} to parse once privileges have been
     * evaluated.
     */
    public void testRawBodyRequestRoundTrip() throws IOException {
        String ruleId = UUID.randomUUID().toString();
        byte[] body = "{\"name\":\"a rule name\"}".getBytes(StandardCharsets.UTF_8);

        IndexCorrelationRuleRequest request =
                new IndexCorrelationRuleRequest(
                        ruleId, RestRequest.Method.POST, body, "application/json");

        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IndexCorrelationRuleRequest newRequest = new IndexCorrelationRuleRequest(sin);

        Assert.assertEquals(ruleId, newRequest.getCorrelationRuleId());
        Assert.assertEquals(RestRequest.Method.POST, newRequest.getMethod());
        Assert.assertNull(
                "the rule is parsed by the transport action, not carried",
                newRequest.getCorrelationRule());
        Assert.assertArrayEquals(body, newRequest.getBody());
        Assert.assertEquals("application/json", newRequest.getMediaType());
    }

    /** The name check the transport action took over from {@code validate()}. */
    public void testIsValidRuleName() {
        Assert.assertFalse(
                "a null name must not dereference",
                IndexCorrelationRuleRequest.isValidRuleName(null));
        Assert.assertFalse(IndexCorrelationRuleRequest.isValidRuleName(""));
        Assert.assertFalse(
                "shorter than five characters",
                IndexCorrelationRuleRequest.isValidRuleName("abcd"));
        Assert.assertFalse(
                "longer than fifty characters",
                IndexCorrelationRuleRequest.isValidRuleName("a".repeat(51)));
        Assert.assertTrue(IndexCorrelationRuleRequest.isValidRuleName("abcde"));
        Assert.assertTrue(
                IndexCorrelationRuleRequest.isValidRuleName(
                        "a rule name, with_the -allowed. chars"));
        Assert.assertFalse(
                "characters outside the allowed set",
                IndexCorrelationRuleRequest.isValidRuleName("bad/name"));
    }

    /** validate() must not touch the body: it runs ahead of the ActionFilters chain. */
    public void testValidateIgnoresTheBody() {
        IndexCorrelationRuleRequest request =
                new IndexCorrelationRuleRequest(
                        CorrelationRule.NO_ID,
                        RestRequest.Method.POST,
                        "{}".getBytes(StandardCharsets.UTF_8),
                        "application/json");
        Assert.assertNull(request.validate());
    }
}
