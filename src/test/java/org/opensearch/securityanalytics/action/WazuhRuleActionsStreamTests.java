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

import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.List;

import com.wazuh.securityanalytics.action.WIndexCustomRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleRequest;
import com.wazuh.securityanalytics.action.WRefreshDetectorsRequest;
import com.wazuh.securityanalytics.action.WRefreshDetectorsResponse;
import com.wazuh.securityanalytics.action.WValidateRuleRequest;
import com.wazuh.securityanalytics.action.WValidateRuleResponse;

/** Wire format of the requests and responses the Content Manager sends for rules and detectors. */
public class WazuhRuleActionsStreamTests extends OpenSearchTestCase {

    private static StreamInput roundTrip(org.opensearch.core.common.io.stream.Writeable w)
            throws IOException {
        BytesStreamOutput out = new BytesStreamOutput();
        w.writeTo(out);
        return out.bytes().streamInput();
    }

    public void testIndexRuleRequestsCarryTheSkipFlag() throws IOException {
        boolean skip = randomBoolean();
        WIndexRuleRequest standard =
                new WIndexRuleRequest(
                        "r1",
                        WriteRequest.RefreshPolicy.IMMEDIATE,
                        "apache-http",
                        RestRequest.Method.POST,
                        "rule",
                        true,
                        "r1",
                        "standard",
                        skip);
        WIndexCustomRuleRequest custom =
                new WIndexCustomRuleRequest(
                        "r1",
                        WriteRequest.RefreshPolicy.IMMEDIATE,
                        "apache-http",
                        RestRequest.Method.PUT,
                        "rule",
                        true,
                        "r1",
                        "custom",
                        skip);
        IndexRuleRequest internal =
                new IndexRuleRequest(
                        "r1",
                        WriteRequest.RefreshPolicy.IMMEDIATE,
                        "apache-http",
                        RestRequest.Method.PUT,
                        "rule",
                        true,
                        "r1",
                        "custom",
                        skip);

        WIndexRuleRequest standardCopy = new WIndexRuleRequest(roundTrip(standard));
        WIndexCustomRuleRequest customCopy = new WIndexCustomRuleRequest(roundTrip(custom));
        IndexRuleRequest internalCopy = new IndexRuleRequest(roundTrip(internal));

        assertEquals(skip, standardCopy.isSkipDetectorRebuild());
        assertEquals(skip, customCopy.isSkipDetectorRebuild());
        assertEquals(skip, internalCopy.isSkipDetectorRebuild());
        assertEquals("custom", customCopy.getSpace());
        assertEquals("r1", internalCopy.getDocumentId());
    }

    public void testIndexRuleRequestsRebuildDetectorsByDefault() {
        assertFalse(
                new WIndexRuleRequest(
                                "r1",
                                WriteRequest.RefreshPolicy.IMMEDIATE,
                                "apache-http",
                                RestRequest.Method.POST,
                                "rule",
                                true,
                                "r1",
                                "standard")
                        .isSkipDetectorRebuild());
        assertFalse(
                new WIndexCustomRuleRequest(
                                "r1",
                                WriteRequest.RefreshPolicy.IMMEDIATE,
                                "apache-http",
                                RestRequest.Method.PUT,
                                "rule",
                                true,
                                "r1",
                                "custom")
                        .isSkipDetectorRebuild());
    }

    public void testRefreshDetectorsRequestAndResponse() throws IOException {
        WRefreshDetectorsRequest request = new WRefreshDetectorsRequest(List.of("r1", "r2"));

        assertEquals(
                List.of("r1", "r2"), new WRefreshDetectorsRequest(roundTrip(request)).getRuleIds());
        assertNull(request.validate());
        assertNotNull(new WRefreshDetectorsRequest(List.of()).validate());
        assertEquals(
                3,
                new WRefreshDetectorsResponse(roundTrip(new WRefreshDetectorsResponse(3))).getDetectors());
    }

    public void testValidateRuleRequestAndResponse() throws IOException {
        WValidateRuleRequest copy =
                new WValidateRuleRequest(roundTrip(new WValidateRuleRequest("Apache-HTTP", "rule", true)));

        assertEquals("apache-http", copy.getLogType());
        assertEquals("rule", copy.getRule());
        assertTrue(copy.isCustom());
        assertNotNull(new WValidateRuleRequest("apache-http", "", false).validate());
        assertEquals(
                List.of("a: 1"),
                new WValidateRuleResponse(roundTrip(new WValidateRuleResponse(List.of("a: 1"))))
                        .getQueries());
    }
}
