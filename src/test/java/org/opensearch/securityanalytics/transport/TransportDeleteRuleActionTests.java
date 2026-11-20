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
package org.opensearch.securityanalytics.transport;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.ScrollableHitSource;
import org.opensearch.test.OpenSearchTestCase;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the space check deciding whether deleting a rule must also strip it from the
 * detectors referencing it, and for the failures a delete-by-query hides inside a successful
 * response.
 */
public class TransportDeleteRuleActionTests extends OpenSearchTestCase {

    /** Deleting the custom copy takes the rule away from detectors, so the references must go. */
    public void testCleansReferencesWhenDeletingTheCustomCopy() {
        assertTrue(TransportDeleteRuleAction.shouldCleanDetectorReferences("custom"));
    }

    /** The space name is compared case-insensitively, as it is where rules are resolved. */
    public void testSpaceComparisonIsCaseInsensitive() {
        assertTrue(TransportDeleteRuleAction.shouldCleanDetectorReferences("CUSTOM"));
    }

    /**
     * Deleting the draft copy leaves the custom copy in place, so detectors still resolve the rule
     * and their references must be left alone.
     */
    public void testKeepsReferencesWhenDeletingTheDraftCopy() {
        assertFalse(TransportDeleteRuleAction.shouldCleanDetectorReferences("draft"));
    }

    /** Same for the test copy. */
    public void testKeepsReferencesWhenDeletingTheTestCopy() {
        assertFalse(TransportDeleteRuleAction.shouldCleanDetectorReferences("test"));
    }

    /** A delete-by-query that deleted everything it matched reports nothing to the caller. */
    public void testNoFailureWhenTheDeleteWentThrough() {
        assertNull(TransportDeleteRuleAction.firstFailure(response(List.of(), List.of())));
    }

    /**
     * The case this guards: an index that blocks writes answers normally, with deleted: 0 and a
     * cluster block per document. Without reading the bulk failures the caller is told the rule was
     * deleted when it is still there.
     */
    public void testReportsTheBulkFailureOfABlockedIndex() {
        BulkItemResponse.Failure blocked =
                new BulkItemResponse.Failure(
                        ".opensearch-sap-pre-packaged-rules-config",
                        "rule-id",
                        new OpenSearchStatusException(
                                "blocked by: [FORBIDDEN/8/index write (api)]", RestStatus.FORBIDDEN));

        String failure = TransportDeleteRuleAction.firstFailure(response(List.of(blocked), List.of()));

        assertNotNull(failure);
        assertTrue(failure.contains("index write (api)"));
    }

    /** A failure on the search half of the delete-by-query is reported too. */
    public void testReportsASearchFailure() {
        ScrollableHitSource.SearchFailure unavailable =
                new ScrollableHitSource.SearchFailure(new IllegalStateException("all shards failed"));

        String failure =
                TransportDeleteRuleAction.firstFailure(response(List.of(), List.of(unavailable)));

        assertNotNull(failure);
        assertTrue(failure.contains("all shards failed"));
    }

    /**
     * A cancelled delete-by-query answers with no failures of either kind, so the failure lists alone
     * would read it as a deletion that went through.
     */
    public void testReportsACancelledTask() {
        BulkByScrollResponse response = response(List.of(), List.of());
        when(response.getReasonCancelled()).thenReturn("by user request");

        String failure = TransportDeleteRuleAction.firstFailure(response);

        assertNotNull(failure);
        assertTrue(failure.contains("by user request"));
    }

    /** Bulk failures are reported first, being the ones that name the document that survived. */
    public void testPrefersTheBulkFailure() {
        BulkItemResponse.Failure bulk =
                new BulkItemResponse.Failure("index", "rule-id", new IllegalStateException("the bulk one"));
        ScrollableHitSource.SearchFailure search =
                new ScrollableHitSource.SearchFailure(new IllegalStateException("the search one"));

        String failure =
                TransportDeleteRuleAction.firstFailure(response(List.of(bulk), List.of(search)));

        assertNotNull(failure);
        assertTrue(failure.contains("the bulk one"));
    }

    /**
     * Builds a delete-by-query response carrying the given failures.
     *
     * @param bulkFailures the failures of the delete half.
     * @param searchFailures the failures of the search half.
     * @return the response.
     */
    private BulkByScrollResponse response(
            List<BulkItemResponse.Failure> bulkFailures,
            List<ScrollableHitSource.SearchFailure> searchFailures) {
        BulkByScrollResponse response = mock(BulkByScrollResponse.class);
        when(response.getBulkFailures()).thenReturn(bulkFailures);
        when(response.getSearchFailures()).thenReturn(searchFailures);
        return response;
    }
}
