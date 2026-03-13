/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;
import org.opensearch.securityanalytics.rules.types.SigmaCIDRExpression;
import org.opensearch.test.OpenSearchTestCase;

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
            "title: Test Rule\n" +
                    "id: 12345678-1234-1234-1234-123456789012\n" +
                    "status: experimental\n" +
                    "description: Top-level description\n" +
                    "author: Test Author\n" +
                    "date: 2024/01/15\n" +
                    "level: high\n" +
                    "logsource:\n" +
                    "    product: windows\n" +
                    "    service: system\n" +
                    "detection:\n" +
                    "    selection:\n" +
                    "        EventID: 16\n" +
                    "    condition: selection\n" +
                    "falsepositives:\n" +
                    "    - Unknown\n" +
                    "metadata:\n" +
                    "    title: Metadata Title Override\n" +
                    "    author: Metadata Author\n" +
                    "    date: '2024-02-01'\n" +
                    "    modified: '2024-03-01'\n" +
                    "    description: Metadata description override\n" +
                    "    references:\n" +
                    "        - https://example.com\n" +
                    "    documentation: https://docs.example.com\n" +
                    "    module: syscheck\n" +
                    "    versions:\n" +
                    "        - '4.8'\n" +
                    "        - '4.9'\n" +
                    "    compatibility:\n" +
                    "        - '>=4.8'\n" +
                    "    supports:\n" +
                    "        - wazuh-4.8\n" +
                    "mitre:\n" +
                    "    tactic:\n" +
                    "        - TA0005\n" +
                    "        - TA0043\n" +
                    "    technique:\n" +
                    "        - T1222\n" +
                    "    subtechnique:\n" +
                    "        - T1222.002\n" +
                    "compliance:\n" +
                    "    pci_dss:\n" +
                    "        - '11.5'\n" +
                    "        - '11.5.1'\n" +
                    "    gdpr:\n" +
                    "        - Article 32\n";


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
        Assert.assertEquals(2, mitre.getTactic().size());
        Assert.assertEquals("TA0005", mitre.getTactic().get(0));
        Assert.assertEquals("TA0043", mitre.getTactic().get(1));
        Assert.assertEquals(1, mitre.getTechnique().size());
        Assert.assertEquals("T1222", mitre.getTechnique().get(0));
        Assert.assertEquals(1, mitre.getSubtechnique().size());
        Assert.assertEquals("T1222.002", mitre.getSubtechnique().get(0));

        // Mitre -> WCS map for indexing
        Map<String, Object> mitreMap = mitre.toMitreMap();
        Assert.assertEquals(List.of("TA0005", "TA0043"), mitreMap.get("tactic"));
        Assert.assertEquals(List.of("T1222", "T1222.002"), mitreMap.get("technique"));
        Assert.assertEquals(List.of("T1222.002"), mitreMap.get("subtechnique"));

        // Compliance
        SigmaCompliance compliance = rule.getCompliance();
        Assert.assertNotNull(compliance);
        Assert.assertEquals(2, compliance.getEntries().size());
        Assert.assertEquals("PCI DSS", compliance.getEntries().get(0).getName());
        Assert.assertEquals(List.of("11.5", "11.5.1"), compliance.getEntries().get(0).getRequirementIds());
        Assert.assertEquals("GDPR", compliance.getEntries().get(1).getName());

        // Compliance -> WCS map
        Map<String, Object> compMap = compliance.toComplianceMap();
        Assert.assertEquals(List.of("11.5", "11.5.1"), compMap.get("pci_dss"));
        Assert.assertEquals(List.of("Article 32"), compMap.get("gdpr"));
    }


    public void testRuleWithoutNewBlocksStillParsesSuccessfully() {
        String yaml =
                "title: Basic Rule\n" +
                        "id: 12345678-1234-1234-1234-123456789012\n" +
                        "status: experimental\n" +
                        "description: Basic\n" +
                        "author: Test\n" +
                        "date: 2024/01/15\n" +
                        "level: high\n" +
                        "logsource:\n" +
                        "    product: windows\n" +
                        "detection:\n" +
                        "    selection:\n" +
                        "        EventID: 16\n" +
                        "    condition: selection\n" +
                        "falsepositives:\n" +
                        "    - Unknown\n";
        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertEquals("Basic Rule", rule.getTitle());
        Assert.assertNull(rule.getMetadata());
        Assert.assertNull(rule.getMitre());
        Assert.assertNull(rule.getCompliance());
    }


    public void testMetadataPartialFields() {
        String yaml =
                "title: Partial Metadata\n" +
                        "id: 12345678-1234-1234-1234-123456789012\n" +
                        "status: experimental\n" +
                        "level: medium\n" +
                        "logsource:\n" +
                        "    product: windows\n" +
                        "detection:\n" +
                        "    selection:\n" +
                        "        EventID: 1\n" +
                        "    condition: selection\n" +
                        "metadata:\n" +
                        "    author: Only Author\n" +
                        "    module: fim\n";
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
                "title: Bad Compliance\n" +
                        "id: 12345678-1234-1234-1234-123456789012\n" +
                        "status: experimental\n" +
                        "level: high\n" +
                        "logsource:\n" +
                        "    product: windows\n" +
                        "detection:\n" +
                        "    selection:\n" +
                        "        EventID: 16\n" +
                        "    condition: selection\n" +
                        "compliance:\n" +
                        "    UNKNOWN_FRAMEWORK:\n" +
                        "        - '1.0'\n";

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().stream()
                .anyMatch(e -> e.getMessage().contains("Unknown compliance framework")));
    }

    public void testUnknownWCSFields() {
        String yaml =
                "title: Unknown Field\n" +
                        "id: 12345678-1234-1234-1234-123456789012\n" +
                        "status: experimental\n" +
                        "level: high\n" +
                        "logsource:\n" +
                        "    product: windows\n" +
                        "detection:\n" +
                        "    selection:\n" +
                        "        totally_fake_field: something\n" +
                        "        another_bad_field|contains: test\n" +
                        "    condition: selection\n";

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().stream()
                .anyMatch(e -> e.getMessage().contains("Unknown WCS fields") &&
                        e.getMessage().contains("totally_fake_field") &&
                        e.getMessage().contains("another_bad_field")));
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

    public void testWCSValidatorKnownField() {
        Assert.assertTrue(WCSFieldValidator.isWCSField("EventID"));
        Assert.assertTrue(WCSFieldValidator.isWCSField("source.ip"));
        Assert.assertTrue(WCSFieldValidator.isWCSField("process.name"));
        Assert.assertTrue(WCSFieldValidator.isWCSField("data.win.eventdata.image"));
    }

    public void testWCSValidatorUnknownField() {
        Assert.assertFalse(WCSFieldValidator.isWCSField("totally_fake_field"));
    }

    public void testWCSValidatorPrefixBasedField() {
        Assert.assertTrue(WCSFieldValidator.isWCSField("event.custom_field"));
        Assert.assertTrue(WCSFieldValidator.isWCSField("data.custom.nested"));
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
                "title: No Subtech\n" +
                        "id: 12345678-1234-1234-1234-123456789012\n" +
                        "status: experimental\n" +
                        "level: high\n" +
                        "logsource:\n" +
                        "    product: windows\n" +
                        "detection:\n" +
                        "    selection:\n" +
                        "        EventID: 16\n" +
                        "    condition: selection\n" +
                        "mitre:\n" +
                        "    tactic:\n" +
                        "        - TA0002\n" +
                        "    technique:\n" +
                        "        - T1059\n";

        SigmaRule rule = SigmaRule.fromYaml(yaml, true);
        Assert.assertTrue(rule.getErrors().getErrors().isEmpty());

        SigmaMitre mitre = rule.getMitre();
        Assert.assertNotNull(mitre);
        Map<String, Object> mitreMap = mitre.toMitreMap();
        Assert.assertEquals(List.of("TA0002"), mitreMap.get("tactic"));
        Assert.assertEquals(List.of("T1059"), mitreMap.get("technique"));
        Assert.assertFalse(mitreMap.containsKey("subtechnique"));
    }
}
