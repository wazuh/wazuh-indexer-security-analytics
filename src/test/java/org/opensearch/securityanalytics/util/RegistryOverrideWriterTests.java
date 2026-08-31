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
package org.opensearch.securityanalytics.util;

import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Assert;

import java.io.IOException;
import java.util.Map;

import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link RegistryOverrideWriter}. */
public class RegistryOverrideWriterTests extends OpenSearchTestCase {

    private static final String DETECTOR_ID = "5315afff-23fc-4aa0-a943-0193de75dabf";

    private Client client;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
    }

    private static Detector standardDetector(boolean enabled) {
        Detector detector = mock(Detector.class);
        when(detector.isStandardDetector()).thenReturn(true);
        when(detector.getEnabled()).thenReturn(enabled);
        return detector;
    }

    @SuppressWarnings("unchecked")
    private UpdateRequest captureWrite() {
        ArgumentCaptor<UpdateRequest> captor = ArgumentCaptor.forClass(UpdateRequest.class);
        verify(this.client).update(captor.capture(), any(ActionListener.class));
        return captor.getValue();
    }

    /** The write targets Content Manager's registry document and upserts it. */
    public void testWritesToTheRegistryDocument() {
        RegistryOverrideWriter.recordDetectorEnabled(this.client, DETECTOR_ID, standardDetector(false));

        UpdateRequest request = captureWrite();
        Assert.assertEquals("wazuh-threatintel-policies", request.index());
        Assert.assertEquals("wazuh-user-overrides", request.id());
        Assert.assertTrue("the registry may not exist yet on the first write", request.docAsUpsert());
        Assert.assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, request.getRefreshPolicy());
    }

    /**
     * The partial document names only this detector's key, so the merge leaves the other integrations
     * and the policy and filters sections alone.
     */
    @SuppressWarnings("unchecked")
    public void testWritesOnlyThisDetectorsKey() throws IOException {
        RegistryOverrideWriter.recordDetectorEnabled(this.client, DETECTOR_ID, standardDetector(false));

        Map<String, Object> doc = captureWrite().doc().sourceAsMap();
        Map<String, Object> overrides = (Map<String, Object>) doc.get("user_overrides");
        Map<String, Object> standard = (Map<String, Object>) overrides.get("standard");
        Map<String, Object> integrations = (Map<String, Object>) standard.get("integrations");

        Assert.assertEquals("only the touched integration may appear", 1, integrations.size());
        Map<String, Object> entry = (Map<String, Object>) integrations.get(DETECTOR_ID);
        Assert.assertEquals(
                "only the detector decision may be written", Map.of("detector_enabled", false), entry);
    }

    /** Starting a detector records {@code true}, not just the absence of a stop. */
    @SuppressWarnings("unchecked")
    public void testStartingADetectorIsRecorded() {
        RegistryOverrideWriter.recordDetectorEnabled(this.client, DETECTOR_ID, standardDetector(true));

        Map<String, Object> doc = captureWrite().doc().sourceAsMap();
        Map<String, Object> overrides = (Map<String, Object>) doc.get("user_overrides");
        Map<String, Object> standard = (Map<String, Object>) overrides.get("standard");
        Map<String, Object> integrations = (Map<String, Object>) standard.get("integrations");

        Assert.assertEquals(Map.of("detector_enabled", true), integrations.get(DETECTOR_ID));
    }

    /**
     * A detector the user created in Security Analytics is left alone: it has no integration behind
     * it, so an override keyed by its id would name something that does not exist.
     */
    @SuppressWarnings("unchecked")
    public void testANonStandardDetectorIsNotRecorded() {
        Detector detector = mock(Detector.class);
        when(detector.isStandardDetector()).thenReturn(false);

        RegistryOverrideWriter.recordDetectorEnabled(this.client, DETECTOR_ID, detector);

        verify(this.client, never()).update(any(UpdateRequest.class), any(ActionListener.class));
    }

    /** A null detector is ignored rather than throwing. */
    @SuppressWarnings("unchecked")
    public void testANullDetectorIsIgnored() {
        RegistryOverrideWriter.recordDetectorEnabled(this.client, DETECTOR_ID, null);

        verify(this.client, never()).update(any(UpdateRequest.class), any(ActionListener.class));
    }

    /**
     * A registry failure must not surface: the detector update itself already succeeded, so throwing
     * here would turn a successful request into an error.
     */
    @SuppressWarnings("unchecked")
    public void testARegistryFailureIsSwallowed() {
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<Object>>getArgument(1)
                                    .onFailure(new IOException("registry unavailable"));
                            return null;
                        })
                .when(this.client)
                .update(any(UpdateRequest.class), any(ActionListener.class));

        RegistryOverrideWriter.recordDetectorEnabled(this.client, DETECTOR_ID, standardDetector(false));
    }
}
