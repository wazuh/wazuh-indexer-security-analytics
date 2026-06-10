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

import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Integration tests for {@code PUT /_plugins/_security_analytics/findings/_update}.
 *
 * <p>These tests exercise the {@link RestUpdateFindingsAction} endpoint that allows updating the
 * {@code wazuh.case} fields on existing finding documents.
 */
public class UpdateFindingsIT extends SecurityAnalyticsRestTestCase {

    private static final String UPDATE_URI = SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_update";
    private static final String CONTENT_TYPE = "application/json";

    // ---------------------------------------------------------------
    // Happy-path tests
    // ---------------------------------------------------------------

    /** Update a single finding with all case fields. Expects HTTP 200 and result "updated". */
    public void testUpdateSingleFinding_allCaseFields() throws IOException {
        String index = createFindingsIndex();
        String docId = indexFindingDoc(index);

        String body =
                "{"
                        + "\"findings\": [{"
                        + "  \"_id\": \""
                        + docId
                        + "\","
                        + "  \"_index\": \""
                        + index
                        + "\","
                        + "  \"case\": {"
                        + "    \"status\": \"ACKNOWLEDGED\","
                        + "    \"comment\": \"Reviewed by analyst\","
                        + "    \"tags\": [\"critical\", \"reviewed\"],"
                        + "    \"created_at\": \"2026-06-10T08:00:00.000Z\","
                        + "    \"updated_at\": \"2026-06-10T09:00:00.000Z\","
                        + "    \"user\": { \"name\": \"analyst1\" }"
                        + "  }"
                        + "}]"
                        + "}";

        Response response = makePutRequest(body);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Map<String, Object> responseBody = entityAsMap(response);
        assertFalse((Boolean) responseBody.get("errors"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) responseBody.get("items");
        assertEquals(1, items.size());
        assertEquals(docId, items.get(0).get("_id"));
        assertEquals("updated", items.get(0).get("result"));

        // Verify the document was actually updated
        Map<String, Object> source = getDocSource(index, docId);
        @SuppressWarnings("unchecked")
        Map<String, Object> wazuh = (Map<String, Object>) source.get("wazuh");
        assertNotNull("wazuh field should exist", wazuh);
        @SuppressWarnings("unchecked")
        Map<String, Object> caseObj = (Map<String, Object>) wazuh.get("case");
        assertNotNull("wazuh.case field should exist", caseObj);
        assertEquals("ACKNOWLEDGED", caseObj.get("status"));
        assertEquals("Reviewed by analyst", caseObj.get("comment"));
        assertEquals("analyst1", ((Map<?, ?>) caseObj.get("user")).get("name"));
    }

    /** Update only the status field — partial case update. */
    public void testUpdateSingleFinding_partialCaseUpdate() throws IOException {
        String index = createFindingsIndex();
        String docId = indexFindingDoc(index);

        String body =
                "{"
                        + "\"findings\": [{"
                        + "  \"_id\": \""
                        + docId
                        + "\","
                        + "  \"_index\": \""
                        + index
                        + "\","
                        + "  \"case\": { \"status\": \"COMPLETED\" }"
                        + "}]"
                        + "}";

        Response response = makePutRequest(body);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Map<String, Object> source = getDocSource(index, docId);
        @SuppressWarnings("unchecked")
        Map<String, Object> caseObj =
                (Map<String, Object>) ((Map<String, Object>) source.get("wazuh")).get("case");
        assertEquals("COMPLETED", caseObj.get("status"));
    }

    /** Bulk update of multiple findings in a single request. */
    public void testUpdateMultipleFindings() throws IOException {
        String index = createFindingsIndex();
        String docId1 = indexFindingDoc(index);
        String docId2 = indexFindingDoc(index);

        String body =
                "{"
                        + "\"findings\": ["
                        + "  { \"_id\": \""
                        + docId1
                        + "\", \"_index\": \""
                        + index
                        + "\", \"case\": { \"status\": \"ACKNOWLEDGED\" } },"
                        + "  { \"_id\": \""
                        + docId2
                        + "\", \"_index\": \""
                        + index
                        + "\", \"case\": { \"status\": \"COMPLETED\" } }"
                        + "]"
                        + "}";

        Response response = makePutRequest(body);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Map<String, Object> responseBody = entityAsMap(response);
        assertFalse((Boolean) responseBody.get("errors"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) responseBody.get("items");
        assertEquals(2, items.size());
    }

    /** Updating a finding that already has case fields should merge/overwrite them. */
    public void testUpdateFinding_overwriteExistingCaseFields() throws IOException {
        String index = createFindingsIndex();
        String docId = indexFindingDoc(index);

        // First update — set status to ACTIVE
        String body1 =
                "{"
                        + "\"findings\": [{"
                        + "  \"_id\": \""
                        + docId
                        + "\","
                        + "  \"_index\": \""
                        + index
                        + "\","
                        + "  \"case\": { \"status\": \"ACTIVE\", \"comment\": \"Initial triage\" }"
                        + "}]"
                        + "}";
        makePutRequest(body1);

        // Second update — overwrite status, add user
        String body2 =
                "{"
                        + "\"findings\": [{"
                        + "  \"_id\": \""
                        + docId
                        + "\","
                        + "  \"_index\": \""
                        + index
                        + "\","
                        + "  \"case\": { \"status\": \"COMPLETED\", \"user\": { \"name\": \"admin\" } }"
                        + "}]"
                        + "}";
        Response response = makePutRequest(body2);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Map<String, Object> source = getDocSource(index, docId);
        @SuppressWarnings("unchecked")
        Map<String, Object> caseObj =
                (Map<String, Object>) ((Map<String, Object>) source.get("wazuh")).get("case");
        assertEquals("COMPLETED", caseObj.get("status"));
        assertEquals("admin", ((Map<?, ?>) caseObj.get("user")).get("name"));
    }

    // ---------------------------------------------------------------
    // Validation / error tests
    // ---------------------------------------------------------------

    /** Empty findings array should return 400. */
    public void testUpdateFindings_emptyArray() throws IOException {
        try {
            makePutRequest("{\"findings\": []}");
            fail("Expected 400 for empty findings array");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Missing findings field should return 400. */
    public void testUpdateFindings_missingFindingsField() throws IOException {
        try {
            makePutRequest("{\"other\": \"value\"}");
            fail("Expected 400 for missing findings field");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Missing _id in a finding element should return 400. */
    public void testUpdateFindings_missingId() throws IOException {
        try {
            makePutRequest(
                    "{\"findings\": [{\"_index\": \"test\", \"case\": {\"status\": \"ACTIVE\"}}]}");
            fail("Expected 400 for missing _id");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Missing _index in a finding element should return 400. */
    public void testUpdateFindings_missingIndex() throws IOException {
        try {
            makePutRequest("{\"findings\": [{\"_id\": \"123\", \"case\": {\"status\": \"ACTIVE\"}}]}");
            fail("Expected 400 for missing _index");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Missing case object in a finding element should return 400. */
    public void testUpdateFindings_missingCaseObject() throws IOException {
        try {
            makePutRequest("{\"findings\": [{\"_id\": \"123\", \"_index\": \"test\"}]}");
            fail("Expected 400 for missing case object");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Invalid JSON body should return 400. */
    public void testUpdateFindings_invalidJson() throws IOException {
        try {
            makePutRequest("not-json");
            fail("Expected 400 for invalid JSON");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Non-existent document ID should result in a response with errors=true (partial failure). */
    public void testUpdateFindings_nonExistentDocument() throws IOException {
        String index = createFindingsIndex();

        String body =
                "{"
                        + "\"findings\": [{"
                        + "  \"_id\": \"nonexistent_doc_id\","
                        + "  \"_index\": \""
                        + index
                        + "\","
                        + "  \"case\": { \"status\": \"ACTIVE\" }"
                        + "}]"
                        + "}";

        Response response = makePutRequest(body);
        // Bulk response with errors — should be 207 MULTI_STATUS
        assertEquals(207, response.getStatusLine().getStatusCode());

        Map<String, Object> responseBody = entityAsMap(response);
        assertTrue((Boolean) responseBody.get("errors"));
    }

    /** Exceeding the MAX_BULK_ITEMS limit (50) should return 400. */
    public void testUpdateFindings_exceedsMaxBulkItems() throws IOException {
        StringBuilder sb = new StringBuilder("{\"findings\": [");
        for (int i = 0; i < 51; i++) {
            if (i > 0) sb.append(",");
            sb.append("{\"_id\": \"id")
                    .append(i)
                    .append("\", \"_index\": \"test\", \"case\": {\"status\": \"ACTIVE\"}}");
        }
        sb.append("]}");

        try {
            makePutRequest(sb.toString());
            fail("Expected 400 for exceeding max bulk items");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    // ---------------------------------------------------------------
    // Response structure tests
    // ---------------------------------------------------------------

    /** Verify the response contains the expected fields: took, errors, items[]. */
    public void testUpdateFindings_responseStructure() throws IOException {
        String index = createFindingsIndex();
        String docId = indexFindingDoc(index);

        String body =
                "{"
                        + "\"findings\": [{"
                        + "  \"_id\": \""
                        + docId
                        + "\","
                        + "  \"_index\": \""
                        + index
                        + "\","
                        + "  \"case\": { \"status\": \"ACTIVE\" }"
                        + "}]"
                        + "}";

        Response response = makePutRequest(body);
        Map<String, Object> responseBody = entityAsMap(response);

        assertTrue("Response should contain 'took'", responseBody.containsKey("took"));
        assertTrue("Response should contain 'errors'", responseBody.containsKey("errors"));
        assertTrue("Response should contain 'items'", responseBody.containsKey("items"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) responseBody.get("items");
        Map<String, Object> item = items.get(0);
        assertTrue("Item should contain '_id'", item.containsKey("_id"));
        assertTrue("Item should contain '_index'", item.containsKey("_index"));
        assertTrue("Item should contain 'status'", item.containsKey("status"));
        assertTrue("Item should contain 'result'", item.containsKey("result"));
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /** Creates a temporary index with a mapping that includes the wazuh.case fields. */
    private String createFindingsIndex() throws IOException {
        String index = "test-findings-" + randomAlphaOfLength(5).toLowerCase();
        String mapping =
                "{"
                        + "\"mappings\": {"
                        + "  \"properties\": {"
                        + "    \"wazuh\": {"
                        + "      \"properties\": {"
                        + "        \"case\": {"
                        + "          \"properties\": {"
                        + "            \"status\": { \"type\": \"keyword\" },"
                        + "            \"comment\": { \"type\": \"text\" },"
                        + "            \"tags\": { \"type\": \"keyword\" },"
                        + "            \"created_at\": { \"type\": \"date\" },"
                        + "            \"updated_at\": { \"type\": \"date\" },"
                        + "            \"user\": {"
                        + "              \"properties\": {"
                        + "                \"name\": { \"type\": \"keyword\" }"
                        + "              }"
                        + "            }"
                        + "          }"
                        + "        },"
                        + "        \"rule\": {"
                        + "          \"properties\": {"
                        + "            \"name\": { \"type\": \"keyword\" }"
                        + "          }"
                        + "        }"
                        + "      }"
                        + "    },"
                        + "    \"timestamp\": { \"type\": \"date\" }"
                        + "  }"
                        + "}"
                        + "}";

        makeRequest(
                client(),
                "PUT",
                index,
                Collections.emptyMap(),
                new StringEntity(mapping),
                new BasicHeader("Content-Type", CONTENT_TYPE));
        return index;
    }

    /** Indexes a minimal finding document and returns its _id. */
    private String indexFindingDoc(String index) throws IOException {
        String doc =
                "{"
                        + "\"wazuh\": {"
                        + "  \"rule\": { \"name\": \"Test Rule\" }"
                        + "},"
                        + "\"timestamp\": \"2026-06-10T08:00:00.000Z\""
                        + "}";

        Response response =
                makeRequest(
                        client(),
                        "POST",
                        index + "/_doc?refresh=true",
                        Collections.emptyMap(),
                        new StringEntity(doc),
                        new BasicHeader("Content-Type", CONTENT_TYPE));
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
        return entityAsMap(response).get("_id").toString();
    }

    /** Fetches a document's _source by index and id. */
    private Map<String, Object> getDocSource(String index, String docId) throws IOException {
        Response response =
                makeRequest(client(), "GET", index + "/_doc/" + docId, Collections.emptyMap(), null);
        @SuppressWarnings("unchecked")
        Map<String, Object> source = (Map<String, Object>) entityAsMap(response).get("_source");
        return source;
    }

    /** Sends a PUT request to the update findings endpoint. */
    private Response makePutRequest(String body) throws IOException {
        return makeRequest(
                client(),
                "PUT",
                UPDATE_URI,
                Collections.emptyMap(),
                new StringEntity(body),
                new BasicHeader("Content-Type", CONTENT_TYPE));
    }
}
