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

import org.opensearch.test.OpenSearchTestCase;

/**
 * Unit tests for the space check deciding whether deleting a rule must also strip it from the
 * detectors referencing it.
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

    /**
     * A rule with no space recorded cannot be attributed to one, so the cleanup still runs. That
     * keeps the stale-reference behaviour for rules predating the space field.
     */
    public void testCleansReferencesWhenTheSpaceIsUnknown() {
        assertTrue(TransportDeleteRuleAction.shouldCleanDetectorReferences(null));
    }
}
