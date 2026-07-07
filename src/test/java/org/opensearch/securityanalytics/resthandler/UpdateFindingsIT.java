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
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.OpenSearchRestTestCase;

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
        String index = this.createFindingsIndex();
        String docId = this.indexFindingDoc(index);

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
                        + "    \"title\": \"Suspicious login\","
                        + "    \"description\": \"Multiple failed logins\","
                        + "    \"status\": \"acknowledged\","
                        + "    \"severity\": \"medium\","
                        + "    \"priority\": \"high\","
                        + "    \"tlp\": \"TLP:AMBER\","
                        + "    \"tags\": [\"critical\", \"reviewed\"],"
                        + "    \"created_at\": \"2026-06-10T08:00:00.000Z\","
                        + "    \"updated_at\": \"2026-06-10T09:00:00.000Z\","
                        + "    \"user\": { \"name\": \"analyst1\" },"
                        + "    \"comments\": [{"
                        + "      \"author\": \"analyst1\","
                        + "      \"comment\": \"Reviewed by analyst\","
                        + "      \"created_at\": \"2026-06-10T09:00:00.000Z\","
                        + "      \"updated_at\": \"2026-06-10T09:00:00.000Z\""
                        + "    }]"
                        + "  }"
                        + "}]"
                        + "}";

        Response response = this.makePutRequest(body);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Map<String, Object> responseBody = OpenSearchRestTestCase.entityAsMap(response);
        assertFalse((Boolean) responseBody.get("errors"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) responseBody.get("items");
        assertEquals(1, items.size());
        assertEquals(docId, items.getFirst().get("_id"));
        assertEquals("updated", items.getFirst().get("result"));

        // Verify the document was actually updated
        Map<String, Object> source = this.getDocSource(index, docId);
        @SuppressWarnings("unchecked")
        Map<String, Object> wazuh = (Map<String, Object>) source.get("wazuh");
        assertNotNull("wazuh field should exist", wazuh);
        @SuppressWarnings("unchecked")
        Map<String, Object> caseObj = (Map<String, Object>) wazuh.get("case");
        assertNotNull("wazuh.case field should exist", caseObj);
        assertEquals("acknowledged", caseObj.get("status"));
        assertEquals("medium", caseObj.get("severity"));
        assertEquals("high", caseObj.get("priority"));
        assertEquals("TLP:AMBER", caseObj.get("tlp"));
        assertEquals("analyst1", ((Map<?, ?>) caseObj.get("user")).get("name"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> comments = (List<Map<String, Object>>) caseObj.get("comments");
        assertEquals(1, comments.size());
        assertEquals("Reviewed by analyst", comments.getFirst().get("comment"));
        assertEquals("analyst1", comments.getFirst().get("author"));
    }

    /** Update only the status field — partial case update. */
    public void testUpdateSingleFinding_partialCaseUpdate() throws IOException {
        String index = this.createFindingsIndex();
        String docId = this.indexFindingDoc(index);

        String body =
                "{"
                        + "\"findings\": [{"
                        + "  \"_id\": \""
                        + docId
                        + "\","
                        + "  \"_index\": \""
                        + index
                        + "\","
                        + "  \"case\": { \"status\": \"completed\" }"
                        + "}]"
                        + "}";

        Response response = this.makePutRequest(body);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Map<String, Object> source = this.getDocSource(index, docId);
        @SuppressWarnings("unchecked")
        Map<String, Object> caseObj =
                (Map<String, Object>) ((Map<String, Object>) source.get("wazuh")).get("case");
        assertEquals("completed", caseObj.get("status"));
    }

    /**
     * Enum values sent in mixed case are normalized: status/severity/priority to lowercase, tlp to
     * uppercase with its prefix.
     */
    public void testUpdateSingleFinding_normalizesEnumCase() throws IOException {
        String index = this.createFindingsIndex();
        String docId = this.indexFindingDoc(index);

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
                        + "    \"severity\": \"High\","
                        + "    \"priority\": \"Urgent\","
                        + "    \"tlp\": \"tlp:green\""
                        + "  }"
                        + "}]"
                        + "}";

        Response response = this.makePutRequest(body);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Map<String, Object> source = this.getDocSource(index, docId);
        @SuppressWarnings("unchecked")
        Map<String, Object> caseObj =
                (Map<String, Object>) ((Map<String, Object>) source.get("wazuh")).get("case");
        assertEquals("acknowledged", caseObj.get("status"));
        assertEquals("high", caseObj.get("severity"));
        assertEquals("urgent", caseObj.get("priority"));
        assertEquals("TLP:GREEN", caseObj.get("tlp"));
    }

    /** Bulk update of multiple findings in a single request. */
    public void testUpdateMultipleFindings() throws IOException {
        String index = this.createFindingsIndex();
        String docId1 = this.indexFindingDoc(index);
        String docId2 = this.indexFindingDoc(index);

        String body =
                "{"
                        + "\"findings\": ["
                        + "  { \"_id\": \""
                        + docId1
                        + "\", \"_index\": \""
                        + index
                        + "\", \"case\": { \"status\": \"acknowledged\" } },"
                        + "  { \"_id\": \""
                        + docId2
                        + "\", \"_index\": \""
                        + index
                        + "\", \"case\": { \"status\": \"completed\" } }"
                        + "]"
                        + "}";

        Response response = this.makePutRequest(body);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Map<String, Object> responseBody = OpenSearchRestTestCase.entityAsMap(response);
        assertFalse((Boolean) responseBody.get("errors"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) responseBody.get("items");
        assertEquals(2, items.size());
    }

    /** Updating a finding that already has case fields should merge/overwrite them. */
    public void testUpdateFinding_overwriteExistingCaseFields() throws IOException {
        String index = this.createFindingsIndex();
        String docId = this.indexFindingDoc(index);

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
                        + "  \"case\": { \"status\": \"active\", \"comments\": [{ \"comment\": \"Initial triage\" }] }"
                        + "}]"
                        + "}";
        this.makePutRequest(body1);

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
                        + "  \"case\": { \"status\": \"completed\", \"user\": { \"name\": \"admin\" } }"
                        + "}]"
                        + "}";
        Response response = this.makePutRequest(body2);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Map<String, Object> source = this.getDocSource(index, docId);
        @SuppressWarnings("unchecked")
        Map<String, Object> caseObj =
                (Map<String, Object>) ((Map<String, Object>) source.get("wazuh")).get("case");
        assertEquals("completed", caseObj.get("status"));
        assertEquals("admin", ((Map<?, ?>) caseObj.get("user")).get("name"));
    }

    // ---------------------------------------------------------------
    // Validation / error tests
    // ---------------------------------------------------------------

    /** Empty findings array should return 400. */
    public void testUpdateFindings_emptyArray() throws IOException {
        try {
            this.makePutRequest("{\"findings\": []}");
            fail("Expected 400 for empty findings array");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Missing findings field should return 400. */
    public void testUpdateFindings_missingFindingsField() throws IOException {
        try {
            this.makePutRequest("{\"other\": \"value\"}");
            fail("Expected 400 for missing findings field");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Missing _id in a finding element should return 400. */
    public void testUpdateFindings_missingId() throws IOException {
        try {
            this.makePutRequest(
                    "{\"findings\": [{\"_index\": \"test\", \"case\": {\"status\": \"ACTIVE\"}}]}");
            fail("Expected 400 for missing _id");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Missing _index in a finding element should return 400. */
    public void testUpdateFindings_missingIndex() throws IOException {
        try {
            this.makePutRequest(
                    "{\"findings\": [{\"_id\": \"123\", \"case\": {\"status\": \"ACTIVE\"}}]}");
            fail("Expected 400 for missing _index");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Missing case object in a finding element should return 400. */
    public void testUpdateFindings_missingCaseObject() throws IOException {
        try {
            this.makePutRequest("{\"findings\": [{\"_id\": \"123\", \"_index\": \"test\"}]}");
            fail("Expected 400 for missing case object");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Invalid JSON body should return 400. */
    public void testUpdateFindings_invalidJson() throws IOException {
        try {
            this.makePutRequest("not-json");
            fail("Expected 400 for invalid JSON");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** Non-existent document ID should result in a response with errors=true (partial failure). */
    public void testUpdateFindings_nonExistentDocument() throws IOException {
        String index = this.createFindingsIndex();

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

        Response response = this.makePutRequest(body);
        // Bulk response with errors — should be 207 MULTI_STATUS
        assertEquals(207, response.getStatusLine().getStatusCode());

        Map<String, Object> responseBody = OpenSearchRestTestCase.entityAsMap(response);
        assertTrue((Boolean) responseBody.get("errors"));
    }

    /** Exceeding the max_case_management_bulk_size limit (default 10) should return 400. */
    public void testUpdateFindings_exceedsMaxBulkItems() throws IOException {
        StringBuilder sb = new StringBuilder("{\"findings\": [");
        for (int i = 0; i < 11; i++) {
            if (i > 0) sb.append(",");
            sb.append("{\"_id\": \"id")
                    .append(i)
                    .append("\", \"_index\": \"test\", \"case\": {\"status\": \"ACTIVE\"}}");
        }
        sb.append("]}");

        try {
            this.makePutRequest(sb.toString());
            fail("Expected 400 for exceeding max bulk items");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    /** An out-of-schema status value should be rejected with 400. */
    public void testUpdateFindings_invalidStatusEnum() throws IOException {
        assertCaseRejected("{ \"status\": \"banana\" }");
    }

    /** An out-of-schema severity value should be rejected with 400. */
    public void testUpdateFindings_invalidSeverityEnum() throws IOException {
        assertCaseRejected("{ \"severity\": \"super-high\" }");
    }

    /** An out-of-schema tlp value should be rejected with 400. */
    public void testUpdateFindings_invalidTlpEnum() throws IOException {
        assertCaseRejected("{ \"tlp\": \"TLP:PURPLE\" }");
    }

    /** An unknown field inside the case object should be rejected with 400. */
    public void testUpdateFindings_unknownCaseField() throws IOException {
        assertCaseRejected("{ \"status\": \"active\", \"foo\": \"bar\" }");
    }

    /** A comments value that is not an array should be rejected with 400. */
    public void testUpdateFindings_commentsNotArray() throws IOException {
        assertCaseRejected("{ \"comments\": \"not-an-array\" }");
    }

    /** An unknown field inside a comment entry should be rejected with 400. */
    public void testUpdateFindings_unknownCommentField() throws IOException {
        assertCaseRejected("{ \"comments\": [{ \"comment\": \"ok\", \"foo\": \"bar\" }] }");
    }

    /** A tags value that is not an array of strings should be rejected with 400. */
    public void testUpdateFindings_invalidTags() throws IOException {
        assertCaseRejected("{ \"tags\": [1, 2, 3] }");
    }

    /**
     * Helper: sends an update with the given raw {@code case} JSON and asserts the endpoint rejects
     * it with a 400 (the finding index is created but no document is required, since validation
     * happens before the bulk request is issued).
     */
    private void assertCaseRejected(String caseJson) throws IOException {
        String index = this.createFindingsIndex();
        String body =
                "{\"findings\": [{ \"_id\": \"any\", \"_index\": \""
                        + index
                        + "\", \"case\": "
                        + caseJson
                        + " }]}";
        try {
            this.makePutRequest(body);
            fail("Expected 400 for invalid case object: " + caseJson);
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    // ---------------------------------------------------------------
    // Response structure tests
    // ---------------------------------------------------------------

    /** Verify the response contains the expected fields: took, errors, items[]. */
    public void testUpdateFindings_responseStructure() throws IOException {
        String index = this.createFindingsIndex();
        String docId = this.indexFindingDoc(index);

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

        Response response = this.makePutRequest(body);
        Map<String, Object> responseBody = OpenSearchRestTestCase.entityAsMap(response);

        assertTrue("Response should contain 'took'", responseBody.containsKey("took"));
        assertTrue("Response should contain 'errors'", responseBody.containsKey("errors"));
        assertTrue("Response should contain 'items'", responseBody.containsKey("items"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) responseBody.get("items");
        Map<String, Object> item = items.getFirst();
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
        String index = "test-findings-" + OpenSearchTestCase.randomAlphaOfLength(5).toLowerCase();
        String mapping =
                "{"
                        + "\"mappings\": {"
                        + "  \"properties\": {"
                        + "    \"wazuh\": {"
                        + "      \"properties\": {"
                        + "        \"case\": {"
                        + "          \"properties\": {"
                        + "            \"title\": { \"type\": \"match_only_text\" },"
                        + "            \"description\": { \"type\": \"match_only_text\" },"
                        + "            \"status\": { \"type\": \"keyword\" },"
                        + "            \"severity\": { \"type\": \"keyword\" },"
                        + "            \"priority\": { \"type\": \"keyword\" },"
                        + "            \"tlp\": { \"type\": \"keyword\" },"
                        + "            \"tags\": { \"type\": \"keyword\" },"
                        + "            \"created_at\": { \"type\": \"date\" },"
                        + "            \"updated_at\": { \"type\": \"date\" },"
                        + "            \"user\": {"
                        + "              \"properties\": {"
                        + "                \"name\": { \"type\": \"keyword\" }"
                        + "              }"
                        + "            },"
                        + "            \"comments\": {"
                        + "              \"type\": \"nested\","
                        + "              \"properties\": {"
                        + "                \"author\": { \"type\": \"keyword\" },"
                        + "                \"comment\": { \"type\": \"match_only_text\" },"
                        + "                \"created_at\": { \"type\": \"date\" },"
                        + "                \"updated_at\": { \"type\": \"date\" }"
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

        this.makeRequest(
                OpenSearchRestTestCase.client(),
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
                this.makeRequest(
                        OpenSearchRestTestCase.client(),
                        "POST",
                        index + "/_doc?refresh=true",
                        Collections.emptyMap(),
                        new StringEntity(doc),
                        new BasicHeader("Content-Type", CONTENT_TYPE));
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
        return OpenSearchRestTestCase.entityAsMap(response).get("_id").toString();
    }

    /** Fetches a document's _source by index and id. */
    private Map<String, Object> getDocSource(String index, String docId) throws IOException {
        Response response =
                this.makeRequest(
                        OpenSearchRestTestCase.client(),
                        "GET",
                        index + "/_doc/" + docId,
                        Collections.emptyMap(),
                        null);
        @SuppressWarnings("unchecked")
        Map<String, Object> source =
                (Map<String, Object>) OpenSearchRestTestCase.entityAsMap(response).get("_source");
        return source;
    }

    /** Sends a PUT request to the update findings endpoint. */
    private Response makePutRequest(String body) throws IOException {
        return this.makeRequest(
                OpenSearchRestTestCase.client(),
                "PUT",
                UPDATE_URI,
                Collections.emptyMap(),
                new StringEntity(body),
                new BasicHeader("Content-Type", CONTENT_TYPE));
    }
}
