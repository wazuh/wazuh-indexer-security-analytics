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
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import com.wazuh.securityanalytics.action.WIndexDetectorRequest;

import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;

public class IndexDetectorRequestTests extends OpenSearchTestCase {

    public void testIndexDetectorPostRequest() throws IOException {
        String detectorId = UUID.randomUUID().toString();
        IndexDetectorRequest request =
                new IndexDetectorRequest(
                        detectorId,
                        WriteRequest.RefreshPolicy.IMMEDIATE,
                        RestRequest.Method.POST,
                        randomDetector(List.of(UUID.randomUUID().toString())));

        Assert.assertNotNull(request);

        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IndexDetectorRequest newRequest = new IndexDetectorRequest(sin);
        Assert.assertEquals(detectorId, request.getDetectorId());
        Assert.assertEquals(RestRequest.Method.POST, newRequest.getMethod());
        Assert.assertNotNull(newRequest.getDetector());
    }

    public void testIndexDetectorPostRequest_2() throws IOException {
        String detectorId = UUID.randomUUID().toString();

        List<String> rules = List.of(UUID.randomUUID().toString());
        DetectorInput input1 =
                new DetectorInput(
                        "windows detector for security analytics",
                        List.of("windows-1"),
                        Collections.emptyList(),
                        rules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        DetectorInput input2 =
                new DetectorInput(
                        "windows detector for security analytics",
                        List.of("windows-2"),
                        Collections.emptyList(),
                        rules.stream().map(DetectorRule::new).collect(Collectors.toList()));

        Detector detector = randomDetectorWithInputs(List.of(input1));
        IndexDetectorRequest request =
                new IndexDetectorRequest(
                        detectorId, WriteRequest.RefreshPolicy.IMMEDIATE, RestRequest.Method.POST, detector);

        Assert.assertNotNull(request);

        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IndexDetectorRequest newRequest = new IndexDetectorRequest(sin);
        Assert.assertEquals(detectorId, request.getDetectorId());
        Assert.assertEquals(RestRequest.Method.POST, newRequest.getMethod());
        Assert.assertNotNull(newRequest.getDetector());
    }

    /**
     * Tests the serialization and deserialization of WIndexDetectorRequest. This ensures that all
     * custom Wazuh fields are correctly preserved when the request is sent over the network between
     * nodes.
     */
    public void testWIndexDetectorRequestSerialization() throws IOException {
        // Prepare mock data for the Wazuh Index Request
        String detectorId = UUID.randomUUID().toString();
        String logTypeName = "apache";
        String category = "web";
        List<String> rules = List.of("rule_1", "rule_2");
        List<String> sources = List.of("wazuh-events-v5-apache");
        int interval = 10;
        boolean enabled = true;
        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.IMMEDIATE;

        // Initialize the request
        WIndexDetectorRequest request =
                new WIndexDetectorRequest(
                        detectorId, logTypeName, category, rules, refreshPolicy, sources, interval, enabled);

        // Serialize the request to a byte stream
        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        // Deserialize the request from the byte stream
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        WIndexDetectorRequest deserializedRequest = new WIndexDetectorRequest(sin);

        // Assert that all fields were preserved during serialization/deserialization
        Assert.assertEquals(
                "Detector ID should match", detectorId, deserializedRequest.getDetectorId());
        Assert.assertEquals(
                "Log type name should match", logTypeName, deserializedRequest.getLogTypeName());
        Assert.assertEquals("Category should match", category, deserializedRequest.getCategory());
        Assert.assertEquals("Rules list should match", rules, deserializedRequest.getRules());
        Assert.assertEquals(
                "Refresh policy should match", refreshPolicy, deserializedRequest.getRefreshPolicy());
        Assert.assertEquals("Sources list should match", sources, deserializedRequest.getSources());
        Assert.assertEquals("Interval should match", interval, deserializedRequest.getInterval());
        Assert.assertEquals("Enabled flag should match", enabled, deserializedRequest.isEnabled());
    }
}
