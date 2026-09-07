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
package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.opensearch.client.ResponseException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.junit.Assert;

import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * The write handlers that parse a request body must answer a body only the client could have
 * produced with 400, not with a 500 carrying a NullPointerException.
 *
 * <p>{@code POST /detectors}, {@code PUT /detectors/{id}} and {@code POST /correlation/rules} used
 * to parse the body in the REST handler and let whatever the parser threw escape as a 500. They now
 * forward the raw body to their transport action, which parses it after the {@code ActionFilters}
 * chain has evaluated the caller's privileges and turns a parse failure into a 400.
 *
 * <p>The ordering half of that change — an account without the write permission being refused with
 * 403 whatever it sends — cannot be asserted here: the integration test cluster runs without the
 * security plugin, so there are no privileges to withhold. What is asserted here is that none of
 * these bodies produces a 5xx and that the reason names the field or token at fault.
 */
public class MalformedRequestBodyRestApiIT extends SecurityAnalyticsRestTestCase {

    /** Bodies that are syntactically valid JSON objects but do not describe the resource. */
    private static final List<String> INCOMPLETE_OBJECTS =
            List.of(
                    "{}",
                    "{\"name\":\"abcdef\"}",
                    "{\"name\":\"abcdef\",\"type\":\"detector\"}",
                    "{\"detector\":{\"name\":\"abcdef\"}}",
                    "{\"name\":\"\"}",
                    "{\"name\":123}",
                    "{\"name\":null}",
                    "{\"unknown_field\":1}");

    /** Bodies that the parser cannot even read as a document of the declared media type. */
    private static final List<String> UNPARSEABLE =
            List.of("[]", "\"a string\"", "42", "null", "{", "{\"name\":");

    private HttpEntity json(String body) {
        return new StringEntity(body, ContentType.APPLICATION_JSON);
    }

    /**
     * Sends a body and asserts it comes back as a 400 rather than a 5xx.
     *
     * @param method the REST method to use
     * @param endpoint the endpoint to send to
     * @param body the raw request body
     * @return the response body, so a caller can assert on the reason
     */
    private String assertBadRequest(String method, String endpoint, String body) {
        ResponseException exception =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest(client(), method, endpoint, Collections.emptyMap(), this.json(body)));
        int status = exception.getResponse().getStatusLine().getStatusCode();
        Assert.assertEquals(
                String.format(
                        Locale.ROOT,
                        "%s %s with body %s should be answered %s, not %s",
                        method,
                        endpoint,
                        body,
                        RestStatus.BAD_REQUEST.getStatus(),
                        status),
                RestStatus.BAD_REQUEST.getStatus(),
                status);
        return exception.getMessage();
    }

    public void testCreateDetectorWithIncompleteBodyIsBadRequest() {
        for (String body : INCOMPLETE_OBJECTS) {
            String response =
                    this.assertBadRequest("POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, body);
            Assert.assertTrue(
                    "the reason should say the body could not be turned into a detector, got: " + response,
                    response.contains("Malformed detector request body"));
        }
    }

    public void testCreateDetectorWithUnparseableBodyIsBadRequest() {
        for (String body : UNPARSEABLE) {
            this.assertBadRequest("POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, body);
        }
    }

    public void testCreateDetectorWithNoBodyIsBadRequest() {
        this.assertBadRequest("POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, "");
    }

    /**
     * The three required fields are reported one by one, each naming itself, rather than surfacing as
     * an unhandled NullPointerException.
     */
    public void testCreateDetectorNamesTheMissingRequiredField() {
        Assert.assertTrue(
                this.assertBadRequest("POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, "{}")
                        .contains("Detector name is null"));
        Assert.assertTrue(
                this.assertBadRequest(
                                "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, "{\"name\":\"abcdef\"}")
                        .contains("Detector schedule is null"));
        Assert.assertTrue(
                this.assertBadRequest(
                                "POST",
                                SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
                                "{\"name\":\"abcdef\",\"schedule\":{\"period\":{\"interval\":1,\"unit\":\"MINUTES\"}}}")
                        .contains("Detector type is null"));
    }

    public void testUpdateDetectorWithMalformedBodyIsBadRequest() {
        String endpoint = SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/does-not-matter";
        for (String body : INCOMPLETE_OBJECTS) {
            this.assertBadRequest("PUT", endpoint, body);
        }
        for (String body : UNPARSEABLE) {
            this.assertBadRequest("PUT", endpoint, body);
        }
        this.assertBadRequest("PUT", endpoint, "");
    }

    public void testCreateCorrelationRuleWithMalformedBodyIsBadRequest() {
        for (String body : UNPARSEABLE) {
            this.assertBadRequest("POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, body);
        }
        this.assertBadRequest("POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, "");
        // A body the parser accepts but that carries no usable name is rejected by the name check the
        // transport action took over from IndexCorrelationRuleRequest.validate().
        Assert.assertTrue(
                this.assertBadRequest("POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, "{}")
                        .contains("Correlation rule name"));
    }

    public void testUpdateCorrelationRuleWithMalformedBodyIsBadRequest() {
        String endpoint = SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/does-not-matter";
        for (String body : UNPARSEABLE) {
            this.assertBadRequest("PUT", endpoint, body);
        }
        this.assertBadRequest("PUT", endpoint, "{}");
        this.assertBadRequest("PUT", endpoint, "");
    }

    /**
     * A trigger that names a detection type the plugin does not support is a client error too. This
     * check moved from the REST handler to the transport action along with the parse, so it is worth
     * pinning that it still answers 400 and still names the trigger.
     */
    public void testCreateDetectorWithUnsupportedTriggerDetectionTypeIsBadRequest() {
        String body =
                "{\"name\":\"abcdef\",\"detector_type\":\"windows\","
                        + "\"schedule\":{\"period\":{\"interval\":1,\"unit\":\"MINUTES\"}},"
                        + "\"inputs\":[],"
                        + "\"triggers\":[{\"id\":\"t1\",\"name\":\"trig\",\"severity\":\"1\","
                        + "\"types\":[],\"ids\":[],\"sev_levels\":[],\"tags\":[],\"actions\":[],"
                        + "\"detection_types\":[\"not_a_real_type\"]}]}";
        String response =
                this.assertBadRequest("POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, body);
        Assert.assertTrue(
                "the reason should name the trigger and the type, got: " + response,
                response.contains("Trigger [trig] has unsupported detection type [not_a_real_type]"));
    }
}
