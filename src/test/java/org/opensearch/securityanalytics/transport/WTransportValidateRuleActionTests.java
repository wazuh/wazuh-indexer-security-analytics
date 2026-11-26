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

import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.rules.objects.WCSFieldValidator;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class WTransportValidateRuleActionTests extends OpenSearchTestCase {

    @Override
    public void tearDown() throws Exception {
        WCSFieldValidator.reset();
        super.tearDown();
    }

    private static String rule(String detection, String condition) {
        return "title: Validate\n"
                + "id: 26a8d32e-0838-5589-948c-501b5a301cf5\n"
                + "status: test\n"
                + "level: low\n"
                + "description: Validate\n"
                + "author: Wazuh\n"
                + "date: 2026/11/26\n"
                + "logsource:\n"
                + "  product: apache-http\n"
                + "detection:\n"
                + detection
                + "  condition: "
                + condition
                + "\n";
    }

    public void testValidStandardRuleReturnsItsQuery() {
        List<String> queries =
                WTransportValidateRuleAction.validate(
                        rule(
                                "  selection:\n"
                                        + "    url.original|contains: .git/\n"
                                        + "  _filt_a177600000_selection:\n"
                                        + "    user_agent.original|startswith: internal-scanner\n",
                                "(selection) and (not _filt_a177600000_selection)"),
                        Collections.emptyMap(),
                        false);

        assertEquals(
                List.of("(url.original: *.git\\/*) AND ((NOT user_agent.original: internal\\-scanner*))"),
                queries);
    }

    public void testValidCustomRuleIsCompiledWithItsFieldMappings() {
        List<String> queries =
                WTransportValidateRuleAction.validate(
                        rule("  selection:\n    url.original|contains: .git/\n", "selection"),
                        Map.of("url.original", "url.full"),
                        true);

        assertEquals(List.of("url.full: *.git\\/*"), queries);
    }

    public void testUndefinedIdentifierIsBadRequest() {
        SecurityAnalyticsException e =
                expectThrows(
                        SecurityAnalyticsException.class,
                        () ->
                                WTransportValidateRuleAction.validate(
                                        rule("  selection:\n    url.original: a\n", "selection and not missing"),
                                        Collections.emptyMap(),
                                        false));

        assertEquals(RestStatus.BAD_REQUEST, e.status());
    }

    public void testFieldOutsideWcsIsBadRequest() {
        WCSFieldValidator.initFromFieldSet(Set.of("url.original"));

        SecurityAnalyticsException e =
                expectThrows(
                        SecurityAnalyticsException.class,
                        () ->
                                WTransportValidateRuleAction.validate(
                                        rule(
                                                "  selection:\n"
                                                        + "    url.original: a\n"
                                                        + "  _filt_a177600000_selection:\n"
                                                        + "    not.a.wcs.field: b\n",
                                                "(selection) and (not _filt_a177600000_selection)"),
                                        Collections.emptyMap(),
                                        false));

        assertEquals(RestStatus.BAD_REQUEST, e.status());
        assertTrue(e.getMessage(), e.getMessage().contains("not.a.wcs.field"));
    }

    public void testQueryThatDoesNotParseIsBadRequest() {
        SecurityAnalyticsException e =
                expectThrows(
                        SecurityAnalyticsException.class,
                        () ->
                                WTransportValidateRuleAction.requireParses(
                                        "(url.original: a) AND ((NOT NOT _exists_: user.name))"));

        assertEquals(RestStatus.BAD_REQUEST, e.status());
        assertTrue(e.getMessage(), e.getMessage().contains("does not parse"));
    }

    public void testQueryThatParsesIsAccepted() {
        WTransportValidateRuleAction.requireParses(
                "(url.original: *.git\\/*) AND ((NOT user_agent.original: internal\\-scanner*))");
    }
}
