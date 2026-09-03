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
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;
import org.opensearch.securityanalytics.rules.types.SigmaCIDRExpression;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class WazuhExtensionsTests extends OpenSearchTestCase {

    @Before
    public void initWCSValidator() {
        Set<String> testFields = new HashSet<>();
        testFields.add("@timestamp");
        testFields.add("message");
        testFields.add("source.ip");
        testFields.add("destination.ip");
        testFields.add("process.name");
        testFields.add("process.pid");
        testFields.add("event.id");
        testFields.add("event.category");
        testFields.add("data.win.eventdata.image");
        testFields.add("data.srcip");
        WCSFieldValidator.initFromFieldSet(testFields);
    }

    @After
    public void resetWCSValidator() {
        WCSFieldValidator.reset();
    }

    private static final String FULL_RULE_YAML =
            "title: Test Rule\n"
                    + "id: 12345678-1234-1234-1234-123456789012\n"
                    + "status: experimental\n"
                    + "description: Top-level description\n"
                    + "author: Test Author\n"
                    + "date: 2024/01/15\n"
                    + "level: high\n"
                    + "logsource:\n"
                    + "    product: windows\n"
                    + "    service: system\n"
                    + "detection:\n"
                    + "    selection:\n"
                    + "        event.id: 16\n"
                    + "    condition: selection\n"
                    + "falsepositives:\n"
                    + "    - Unknown\n"
                    + "metadata:\n"
                    + "    title: Metadata Title Override\n"
                    + "    author: Metadata Author\n"
                    + "    date: '2024-02-01'\n"
                    + "    modified: '2024-03-01'\n"
                    + "    description: Metadata description override\n"
                    + "    references:\n"
                    + "        - https://example.com\n"
                    + "    documentation: https://docs.example.com\n"
                    + "    module: syscheck\n"
                    + "    versions:\n"
                    + "        - '4.8'\n"
                    + "        - '4.9'\n"
                    + "    compatibility:\n"
                    + "        - '>=4.8'\n"
                    + "    supports:\n"
                    + "        - wazuh-4.8\n"
                    + "mitre:\n"
                    + "    tactic:\n"
                    + "        id:\n"
                    + "            - TA0005\n"
                    + "            - TA0043\n"
                    + "        name:\n"
                    + "            - Defense Evasion\n"
                    + "            - Reconnaissance\n"
                    + "    technique:\n"
                    + "        id:\n"
                    + "            - T1222\n"
                    + "        name:\n"
                    + "            - File and Directory Permissions Modification\n"
                    + "    subtechnique:\n"
                    + "        id:\n"
                    + "            - T1222.002\n"
                    + "        name:\n"
                    + "            - 'File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification'\n"
                    + "compliance:\n"
                    + "    pci_dss:\n"
                    + "        - '11.5'\n"
                    + "        - '11.5.1'\n"
                    + "    gdpr:\n"
                    + "        - Article 32\n";

    public void testFullRuleParsing() {
        SigmaRule rule = SigmaRule.fromYaml(FULL_RULE_YAML, true);

        // Metadata title/description override top-level
        Assert.assertEquals("Metadata Title Override", rule.getTitle());
        Assert.assertEquals("Metadata description override", rule.getDescription());

        // Metadata fields
        SigmaMetadata meta = rule.getMetadata();
        Assert.assertNotNull(meta);
        Assert.assertEquals("Metadata Author", meta.getAuthor());
        Assert.assertEquals("2024-02-01", meta.getDate());
        Assert.assertEquals("2024-03-01", meta.getModified());
        Assert.assertEquals("syscheck", meta.getModule());
        Assert.assertEquals(List.of("4.8", "4.9"), meta.getVersions());
        Assert.assertEquals(List.of(">=4.8"), meta.getCompatibility());
        Assert.assertEquals(List.of("wazuh-4.8"), meta.getSupports());
        Assert.assertEquals(List.of("https://example.com"), meta.getReferences());
        Assert.assertEquals("https://docs.example.com", meta.getDocumentation());

        // Mitre (updated from Threat)
        SigmaMitre mitre = rule.getMitre();
        Assert.assertNotNull(mitre);
        Assert.assertEquals(2, mitre.getTacticId().size());
        Assert.assertEquals("TA0005", mitre.getTacticId().get(0));
        Assert.assertEquals("TA0043", mitre.getTacticId().get(1));
        Assert.assertEquals(2, mitre.getTacticName().size());
        Assert.assertEquals("Defense Evasion", mitre.getTacticName().get(0));
        Assert.assertEquals("Reconnaissance", mitre.getTacticName().get(1));
        Assert.assertEquals(1, mitre.getTechniqueId().size());
        Assert.assertEquals("T1222", mitre.getTechniqueId().get(0));
        Assert.assertEquals(1, mitre.getTechniqueName().size());
        Assert.assertEquals(
                "File and Directory Permissions Modification", mitre.getTechniqueName().get(0));
        Assert.assertEquals(1, mitre.getSubtechniqueId().size());
        Assert.assertEquals("T1222.002", mitre.getSubtechniqueId().get(0));

        // Mitre -> WCS map for indexing (nested structure)
        Map<String, Object> mitreMap = mitre.toMitreMap();
        @SuppressWarnings("unchecked")
        Map<String, Object> tacticMap = (Map<String, Object>) mitreMap.get("tactic");
        Assert.assertEquals(List.of("TA0005", "TA0043"), tacticMap.get("id"));
        Assert.assertEquals(List.of("Defense Evasion", "Reconnaissance"), tacticMap.get("name"));
        @SuppressWarnings("unchecked")
        Map<String, Object> techniqueMap = (Map<String, Object>) mitreMap.get("technique");
        Assert.assertEquals(List.of("T1222", "T1222.002"), techniqueMap.get("id"));
        @SuppressWarnings("unchecked")
        Map<String, Object> subtechniqueMap = (Map<String, Object>) mitreMap.get("subtechnique");
        Assert.assertEquals(List.of("T1222.002"), subtechniqueMap.get("id"));

        // Compliance
        SigmaCompliance compliance = rule.getCompliance();
        Assert.assertNotNull(compliance);
        Assert.assertEquals(2, compliance.getEntries().size());
        Assert.assertEquals("PCI DSS", compliance.getEntries().get(0).getName());
        Assert.assertEquals(
                List.of("11.5", "11.5.1"), compliance.getEntries().get(0).getRequirementIds());
        Assert.assertEquals("GDPR", compliance.getEntries().get(1).getName());

        // Compliance -> WCS map
        Map<String, Object> compMap = compliance.toComplianceMap();
        Assert.assertEquals(List.of("11.5", "11.5.1"), compMap.get("pci_dss"));
        Assert.assertEquals(List.of("Article 32"), compMap.get("gdpr"));
    }

    public void testRuleWithoutNewBlocksStillParsesSuccessfully() {
        String yaml =
                "title: Basic Rule\n"
                        + "id: 12345678-1234-1234-1234-123456789012\n"
                        + "status: experimental\n"
                        + "description: Basic\n"
                        + "author: Test\n"
                        + "date: 2024/01/15\n"
                        + "level: high\n"
                        + "logsource:\n"
                        + "    product: windows\n"
                        + "detection:\n"
                        + "    selection:\n"
                        + "        event.id: 16\n"
                        + "    condition: selection\n"
                        + "falsepositives:\n"
                        + "    - Unknown\n";
        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertEquals("Basic Rule", rule.getTitle());
        Assert.assertNull(rule.getMetadata());
        Assert.assertNull(rule.getMitre());
        Assert.assertNull(rule.getCompliance());
    }

    public void testMetadataPartialFields() {
        String yaml =
                "title: Partial Metadata\n"
                        + "id: 12345678-1234-1234-1234-123456789012\n"
                        + "status: experimental\n"
                        + "level: medium\n"
                        + "logsource:\n"
                        + "    product: windows\n"
                        + "detection:\n"
                        + "    selection:\n"
                        + "        event.id: 1\n"
                        + "    condition: selection\n"
                        + "metadata:\n"
                        + "    author: Only Author\n"
                        + "    module: fim\n";
        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        SigmaMetadata meta = rule.getMetadata();
        Assert.assertNotNull(meta);
        Assert.assertEquals("Only Author", meta.getAuthor());
        Assert.assertEquals("fim", meta.getModule());
        Assert.assertNull(meta.getTitle());
        Assert.assertTrue(meta.getVersions().isEmpty());
        Assert.assertTrue(meta.getCompatibility().isEmpty());
        Assert.assertTrue(meta.getSupports().isEmpty());
        // Title should NOT be overridden since metadata.title is null
        Assert.assertEquals("Partial Metadata", rule.getTitle());
    }

    public void testUnknownComplianceFramework() {
        String yaml =
                "title: Bad Compliance\n"
                        + "id: 12345678-1234-1234-1234-123456789012\n"
                        + "status: experimental\n"
                        + "level: high\n"
                        + "logsource:\n"
                        + "    product: windows\n"
                        + "detection:\n"
                        + "    selection:\n"
                        + "        event.id: 16\n"
                        + "    condition: selection\n"
                        + "compliance:\n"
                        + "    UNKNOWN_FRAMEWORK:\n"
                        + "        - '1.0'\n";

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(
                rule.getErrors().getErrors().stream()
                        .anyMatch(e -> e.getMessage().contains("Unknown compliance framework")));
    }

    public void testUnknownWCSFields() {
        String yaml =
                "title: Unknown Field\n"
                        + "id: 12345678-1234-1234-1234-123456789012\n"
                        + "status: experimental\n"
                        + "level: high\n"
                        + "logsource:\n"
                        + "    product: windows\n"
                        + "detection:\n"
                        + "    selection:\n"
                        + "        totally_fake_field: something\n"
                        + "        another_bad_field|contains: test\n"
                        + "    condition: selection\n";

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(
                rule.getErrors().getErrors().stream()
                        .anyMatch(
                                e ->
                                        e.getMessage()
                                                        .contains(
                                                                "The following fields are not part of the Wazuh Common Schema (WCS)")
                                                && e.getMessage().contains("totally_fake_field")
                                                && e.getMessage().contains("another_bad_field")));
    }

    public void testIPv6Standard() throws SigmaTypeError {
        SigmaCIDRExpression expr = new SigmaCIDRExpression("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        Assert.assertTrue(expr.isIpv6());
    }

    public void testIPv6Compressed() throws SigmaTypeError {
        SigmaCIDRExpression expr = new SigmaCIDRExpression("2001:db8::1");
        Assert.assertTrue(expr.isIpv6());
    }

    public void testIPv6DoubleColon() throws SigmaTypeError {
        SigmaCIDRExpression expr = new SigmaCIDRExpression("::");
        Assert.assertTrue(expr.isIpv6());
    }

    public void testIPv6Loopback() throws SigmaTypeError {
        SigmaCIDRExpression expr = new SigmaCIDRExpression("::1");
        Assert.assertTrue(expr.isIpv6());
    }

    public void testIPv6CIDR() throws SigmaTypeError {
        SigmaCIDRExpression expr = new SigmaCIDRExpression("2001:db8::/32");
        Assert.assertTrue(expr.isIpv6());
        Assert.assertEquals("2001:db8::/32", expr.getCidr());
    }

    public void testIPv6CIDRFe80() throws SigmaTypeError {
        SigmaCIDRExpression expr = new SigmaCIDRExpression("fe80::/10");
        Assert.assertTrue(expr.isIpv6());
    }

    public void testIPv4StillWorks() throws SigmaTypeError {
        SigmaCIDRExpression expr = new SigmaCIDRExpression("192.168.1.0/24");
        Assert.assertFalse(expr.isIpv6());
    }

    public void testInvalidCIDRThrows() {
        assertThrows(SigmaTypeError.class, () -> new SigmaCIDRExpression("not-an-ip"));
    }

    public void testIPv6InvalidPrefixThrows() {
        assertThrows(SigmaTypeError.class, () -> new SigmaCIDRExpression("2001:db8::/200"));
    }

    public void testIPv4NonNumericPrefixThrows() {
        assertThrows(SigmaTypeError.class, () -> new SigmaCIDRExpression("192.168.1.0/xx"));
    }

    public void testWCSValidatorKnownField() {
        Assert.assertTrue(WCSFieldValidator.isWCSField("event.id"));
        Assert.assertTrue(WCSFieldValidator.isWCSField("source.ip"));
        Assert.assertTrue(WCSFieldValidator.isWCSField("process.name"));
        Assert.assertTrue(WCSFieldValidator.isWCSField("data.win.eventdata.image"));
    }

    public void testWCSValidatorUnknownField() {
        Assert.assertFalse(WCSFieldValidator.isWCSField("totally_fake_field"));
    }

    public void testWCSValidatorPrefixBasedField() {
        Assert.assertFalse(WCSFieldValidator.isWCSField("event.custom_field"));
        Assert.assertFalse(WCSFieldValidator.isWCSField("data.custom.nested"));
    }

    public void testWCSValidatorUninitializedAcceptsAll() {
        WCSFieldValidator.reset();
        Assert.assertTrue(WCSFieldValidator.isWCSField("totally_fake_field"));
    }

    public void testFrameworkKeyNormalization() {
        Assert.assertEquals("pci_dss", SigmaCompliance.normalizeFrameworkKey("PCI DSS"));
        Assert.assertEquals("nist_800_53", SigmaCompliance.normalizeFrameworkKey("NIST 800-53"));
        Assert.assertEquals("iso_27001", SigmaCompliance.normalizeFrameworkKey("ISO 27001"));
        Assert.assertEquals("gdpr", SigmaCompliance.normalizeFrameworkKey("GDPR"));
        Assert.assertEquals("fedramp", SigmaCompliance.normalizeFrameworkKey("FedRAMP"));
    }

    public void testThreatMitreMapNoSubtechniques() {
        String yaml =
                "title: No Subtech\n"
                        + "id: 12345678-1234-1234-1234-123456789012\n"
                        + "status: experimental\n"
                        + "level: high\n"
                        + "logsource:\n"
                        + "    product: windows\n"
                        + "detection:\n"
                        + "    selection:\n"
                        + "        event.id: 16\n"
                        + "    condition: selection\n"
                        + "mitre:\n"
                        + "    tactic:\n"
                        + "        id:\n"
                        + "            - TA0002\n"
                        + "        name:\n"
                        + "            - Execution\n"
                        + "    technique:\n"
                        + "        id:\n"
                        + "            - T1059\n"
                        + "        name:\n"
                        + "            - Command and Scripting Interpreter\n";

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().isEmpty());

        SigmaMitre mitre = rule.getMitre();
        Assert.assertNotNull(mitre);
        Map<String, Object> mitreMap = mitre.toMitreMap();
        @SuppressWarnings("unchecked")
        Map<String, Object> tacticMap = (Map<String, Object>) mitreMap.get("tactic");
        Assert.assertEquals(List.of("TA0002"), tacticMap.get("id"));
        Assert.assertEquals(List.of("Execution"), tacticMap.get("name"));
        @SuppressWarnings("unchecked")
        Map<String, Object> techniqueMap = (Map<String, Object>) mitreMap.get("technique");
        Assert.assertEquals(List.of("T1059"), techniqueMap.get("id"));
        Assert.assertEquals(List.of("Command and Scripting Interpreter"), techniqueMap.get("name"));
        Assert.assertFalse(mitreMap.containsKey("subtechnique"));
    }

    /** Builds a minimal valid rule with the supplied {@code mitre} block appended. */
    private static String ruleWithMitreBlock(String mitreBlock) {
        return "title: Mitre Shape\n"
                + "id: 22345678-1234-1234-1234-123456789012\n"
                + "status: experimental\n"
                + "level: high\n"
                + "logsource:\n"
                + "    product: windows\n"
                + "detection:\n"
                + "    selection:\n"
                + "        event.id: 16\n"
                + "    condition: selection\n"
                + mitreBlock;
    }

    /**
     * The deprecated shorthand, in which each category is a plain array of ID strings, must be parsed
     * into the nested WCS structure with empty name arrays. This is the format documented before the
     * id/name structure was introduced, and the one reported in wazuh/wazuh#37939.
     */
    public void testMitreLegacyFlatShorthandIsParsed() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n"
                                + "    tactic:\n"
                                + "        - TA0007\n"
                                + "    technique:\n"
                                + "        - T1518\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().isEmpty());

        SigmaMitre mitre = rule.getMitre();
        Assert.assertNotNull(mitre);
        Assert.assertEquals(List.of("TA0007"), mitre.getTacticId());
        Assert.assertEquals(List.of(), mitre.getTacticName());
        Assert.assertEquals(List.of("T1518"), mitre.getTechniqueId());
        Assert.assertEquals(List.of(), mitre.getTechniqueName());

        Map<String, Object> mitreMap = mitre.toMitreMap();
        @SuppressWarnings("unchecked")
        Map<String, Object> tacticMap = (Map<String, Object>) mitreMap.get("tactic");
        Assert.assertEquals(List.of("TA0007"), tacticMap.get("id"));
        Assert.assertFalse(tacticMap.containsKey("name"));
        @SuppressWarnings("unchecked")
        Map<String, Object> techniqueMap = (Map<String, Object>) mitreMap.get("technique");
        Assert.assertEquals(List.of("T1518"), techniqueMap.get("id"));
        Assert.assertFalse(techniqueMap.containsKey("name"));
    }

    /** The shorthand must also carry subtechniques. */
    public void testMitreLegacyFlatShorthandWithSubtechnique() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n"
                                + "    tactic:\n"
                                + "        - TA0001\n"
                                + "    technique:\n"
                                + "        - T1190\n"
                                + "    subtechnique:\n"
                                + "        - T1190.001\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().isEmpty());

        SigmaMitre mitre = rule.getMitre();
        Assert.assertNotNull(mitre);
        Assert.assertEquals(List.of("T1190.001"), mitre.getSubtechniqueId());
    }

    /** An explicitly empty category is legitimate and must not raise an error. */
    public void testMitreEmptyCategoryIsAccepted() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n" + "    tactic:\n" + "        - TA0001\n" + "    subtechnique: []\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().isEmpty());
        Assert.assertEquals(List.of("TA0001"), rule.getMitre().getTacticId());
        Assert.assertEquals(List.of(), rule.getMitre().getSubtechniqueId());
    }

    /** The nested and shorthand forms may be mixed across categories. */
    public void testMitreMixedNestedAndShorthandForms() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n"
                                + "    tactic:\n"
                                + "        id:\n"
                                + "            - TA0002\n"
                                + "        name:\n"
                                + "            - Execution\n"
                                + "    technique:\n"
                                + "        - T1059\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().isEmpty());

        SigmaMitre mitre = rule.getMitre();
        Assert.assertEquals(List.of("TA0002"), mitre.getTacticId());
        Assert.assertEquals(List.of("Execution"), mitre.getTacticName());
        Assert.assertEquals(List.of("T1059"), mitre.getTechniqueId());
        Assert.assertEquals(List.of(), mitre.getTechniqueName());
    }

    /** Asserts the rule collected at least one error whose message contains {@code substring}. */
    private static void assertErrorContaining(SigmaRule rule, String substring) {
        boolean found =
                rule.getErrors().getErrors().stream()
                        .map(Throwable::getMessage)
                        .filter(java.util.Objects::nonNull)
                        .anyMatch(message -> message.contains(substring));
        Assert.assertTrue(
                "expected an error containing \""
                        + substring
                        + "\" but got "
                        + rule.getErrors().getErrors(),
                found);
    }

    /** An unrecognized category must be reported rather than silently discarded. */
    public void testMitreUnknownCategoryIsReported() {
        String yaml = ruleWithMitreBlock("mitre:\n" + "    tactics:\n" + "        - TA0007\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        assertErrorContaining(rule, "mitre.tactics");
    }

    /** A misspelled key inside a category must be reported rather than silently discarded. */
    public void testMitreUnknownCategoryKeyIsReported() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n" + "    tactic:\n" + "        ids:\n" + "            - TA0007\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        assertErrorContaining(rule, "ids");
    }

    /** A mitre block that is not an object must be reported, not raise ClassCastException. */
    public void testMitreBlockNotAnObjectIsReported() {
        String yaml = ruleWithMitreBlock("mitre:\n" + "    - TA0007\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        assertErrorContaining(rule, "Mitre block must be");
    }

    /**
     * End-to-end check of the exact rule reported in wazuh/wazuh#37939: the shorthand mitre block
     * must survive into the map the finding enrichment writes to {@code wazuh.rule.mitre}.
     */
    public void testMitreIssue37939ReportedRule() {
        String yaml =
                "title: Custom IT Hygiene hardware stat modified\n"
                        + "id: b940f93b-8fb5-409f-96c5-f06a55480912\n"
                        + "status: stable\n"
                        + "level: informational\n"
                        + "logsource:\n"
                        + "    product: windows\n"
                        + "detection:\n"
                        + "    selection:\n"
                        + "        event.id: 16\n"
                        + "    condition: selection\n"
                        + "tags:\n"
                        + "    - attack.discovery\n"
                        + "    - attack.t1518\n"
                        + "mitre:\n"
                        + "    tactic:\n"
                        + "        - TA0007\n"
                        + "    technique:\n"
                        + "        - T1518\n";

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().isEmpty());

        Map<String, Object> mitreMap = rule.getMitre().toMitreMap();
        Assert.assertFalse("mitre map must not be empty", mitreMap.isEmpty());
        @SuppressWarnings("unchecked")
        Map<String, Object> tacticMap = (Map<String, Object>) mitreMap.get("tactic");
        Assert.assertEquals(List.of("TA0007"), tacticMap.get("id"));
        @SuppressWarnings("unchecked")
        Map<String, Object> techniqueMap = (Map<String, Object>) mitreMap.get("technique");
        Assert.assertEquals(List.of("T1518"), techniqueMap.get("id"));
    }

    /**
     * Each category may be an array of per-entry {id, name} objects, which pairs every ATT&amp;CK ID
     * with its name directly. It must flatten into the same parallel arrays as the nested form, and
     * must not be mistaken for the deprecated ID-string shorthand.
     */
    public void testMitreEntryObjectArrayIsParsed() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n"
                                + "    tactic:\n"
                                + "        - id: TA0006\n"
                                + "          name: Credential Access\n"
                                + "    technique:\n"
                                + "        - id: T1555\n"
                                + "          name: Credentials from Password Stores\n"
                                + "    subtechnique:\n"
                                + "        - id: T1555.005\n"
                                + "          name: Password Managers\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().isEmpty());

        SigmaMitre mitre = rule.getMitre();
        Assert.assertEquals(List.of("TA0006"), mitre.getTacticId());
        Assert.assertEquals(List.of("Credential Access"), mitre.getTacticName());
        Assert.assertEquals(List.of("T1555"), mitre.getTechniqueId());
        Assert.assertEquals(List.of("Credentials from Password Stores"), mitre.getTechniqueName());
        Assert.assertEquals(List.of("T1555.005"), mitre.getSubtechniqueId());
        Assert.assertEquals(List.of("Password Managers"), mitre.getSubtechniqueName());

        Map<String, Object> mitreMap = mitre.toMitreMap();
        @SuppressWarnings("unchecked")
        Map<String, Object> tacticMap = (Map<String, Object>) mitreMap.get("tactic");
        Assert.assertEquals(List.of("TA0006"), tacticMap.get("id"));
        Assert.assertEquals(List.of("Credential Access"), tacticMap.get("name"));
        @SuppressWarnings("unchecked")
        Map<String, Object> techniqueMap = (Map<String, Object>) mitreMap.get("technique");
        Assert.assertEquals(List.of("T1555", "T1555.005"), techniqueMap.get("id"));
        Assert.assertEquals(
                List.of("Credentials from Password Stores", "Password Managers"), techniqueMap.get("name"));
    }

    /** Several entries in one category must preserve their order across the id and name arrays. */
    public void testMitreEntryObjectArrayWithMultipleEntries() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n"
                                + "    tactic:\n"
                                + "        - id: TA0006\n"
                                + "          name: Credential Access\n"
                                + "        - id: TA0007\n"
                                + "          name: Discovery\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().isEmpty());
        Assert.assertEquals(List.of("TA0006", "TA0007"), rule.getMitre().getTacticId());
        Assert.assertEquals(List.of("Credential Access", "Discovery"), rule.getMitre().getTacticName());
    }

    /** Entry objects carrying only an id are valid and leave the name array empty. */
    public void testMitreEntryObjectArrayWithoutNames() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n" + "    tactic:\n" + "        - id: TA0006\n" + "        - id: TA0007\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().isEmpty());
        Assert.assertEquals(List.of("TA0006", "TA0007"), rule.getMitre().getTacticId());
        Assert.assertEquals(List.of(), rule.getMitre().getTacticName());
    }

    /**
     * The id and name arrays are positional, so naming only some entries would misalign them. That
     * must be reported instead of silently producing arrays of different lengths.
     */
    public void testMitrePartiallyNamedEntriesAreReported() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n"
                                + "    tactic:\n"
                                + "        - id: TA0006\n"
                                + "          name: Credential Access\n"
                                + "        - id: TA0007\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        assertErrorContaining(rule, "'name' for only some entries");
    }

    /** An entry object without an id carries no usable ATT&amp;CK reference and must be reported. */
    public void testMitreEntryObjectWithoutIdIsReported() {
        String yaml =
                ruleWithMitreBlock("mitre:\n" + "    tactic:\n" + "        - name: Credential Access\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        assertErrorContaining(rule, "is missing 'id'");
    }

    /** A misspelled key inside an entry object must be reported, as it is for the nested form. */
    public void testMitreEntryObjectUnknownKeyIsReported() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n"
                                + "    tactic:\n"
                                + "        - id: TA0006\n"
                                + "          label: Credential Access\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        assertErrorContaining(rule, "label");
    }

    /**
     * Mixing bare ID strings with entry objects in one array is ambiguous — the names could not be
     * aligned with the IDs — so it must be reported rather than partially parsed.
     */
    public void testMitreMixedArrayElementsAreReported() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n"
                                + "    tactic:\n"
                                + "        - TA0006\n"
                                + "        - id: TA0007\n"
                                + "          name: Discovery\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        assertErrorContaining(rule, "mixes ID strings");
    }

    /**
     * A nested id/name array holding objects instead of scalars must be reported. Previously such
     * values were rendered with {@code toString()}, indexing a literal "{id=..., name=...}" as the
     * ATT&amp;CK ID.
     */
    public void testMitreNestedArrayOfObjectsIsReported() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n"
                                + "    tactic:\n"
                                + "        id:\n"
                                + "            - id: TA0006\n"
                                + "              name: Credential Access\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        assertErrorContaining(rule, "must be a single value");
    }

    /** No parsed ID or name may ever contain a stringified map, whichever form was supplied. */
    public void testMitreNeverStringifiesStructures() {
        String yaml =
                ruleWithMitreBlock(
                        "mitre:\n"
                                + "    tactic:\n"
                                + "        - id: TA0006\n"
                                + "          name: Credential Access\n"
                                + "    technique:\n"
                                + "        - id: T1555\n"
                                + "          name: Credentials from Password Stores\n");

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        SigmaMitre mitre = rule.getMitre();

        List<String> values = new java.util.ArrayList<>();
        values.addAll(mitre.getTacticId());
        values.addAll(mitre.getTacticName());
        values.addAll(mitre.getTechniqueId());
        values.addAll(mitre.getTechniqueName());
        Assert.assertFalse(values.isEmpty());
        for (String value : values) {
            Assert.assertFalse("value was stringified from a structure: " + value, value.contains("id="));
        }
    }
}
