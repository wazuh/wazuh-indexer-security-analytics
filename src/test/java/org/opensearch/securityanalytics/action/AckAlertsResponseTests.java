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
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

public class AckAlertsResponseTests extends OpenSearchTestCase {

    public void testStreamInOut() throws IOException {
        AlertDto alertDto1 = geRandomAlertDto();
        AlertDto alertDto2 = geRandomAlertDto();
        AlertDto alertDto3 = geRandomAlertDto();
        AlertDto alertDto4 = geRandomAlertDto();
        AckAlertsResponse response =
                new AckAlertsResponse(
                        Arrays.asList(alertDto1, alertDto2),
                        Arrays.asList(alertDto3, alertDto4),
                        Arrays.asList("1", "2", "3"));
        BytesStreamOutput out = new BytesStreamOutput();
        response.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        AckAlertsResponse ackAlertsResponse = new AckAlertsResponse(sin);
        assertEquals(ackAlertsResponse.getAcknowledged().size(), 2);
        assertEquals(
                ackAlertsResponse.getAcknowledged().get(0).getDetectorId(), alertDto1.getDetectorId());
        assertEquals(
                ackAlertsResponse.getAcknowledged().get(1).getDetectorId(), alertDto2.getDetectorId());
        assertEquals(ackAlertsResponse.getFailed().size(), 2);
        assertEquals(ackAlertsResponse.getFailed().get(0).getDetectorId(), alertDto3.getDetectorId());
        assertEquals(ackAlertsResponse.getFailed().get(1).getDetectorId(), alertDto4.getDetectorId());
        assertEquals(ackAlertsResponse.getMissing().size(), 3);
    }

    private AlertDto geRandomAlertDto() {
        return new AlertDto(
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                -1L,
                1,
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                Arrays.asList(UUID.randomUUID().toString()),
                Arrays.asList(UUID.randomUUID().toString()),
                Alert.State.ACTIVE,
                Instant.now(),
                Instant.now(),
                Instant.now(),
                Instant.now(),
                null,
                Collections.emptyList(),
                "1",
                Collections.emptyList(),
                null);
    }
}
