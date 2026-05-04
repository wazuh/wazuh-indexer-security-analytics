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
package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RuleMetadataTests extends OpenSearchTestCase {

    private RuleMetadata populated() {
        return new RuleMetadata(
                "Suspicious PowerShell",
                "wazuh",
                "2025-01-01",
                "2025-02-01",
                "Detects suspicious PowerShell invocation",
                Arrays.asList("https://example.com/a", "https://example.com/b"),
                "https://docs.example.com/rule",
                "wazuh-core",
                Arrays.asList("4.8.0", "4.9.0"),
                Arrays.asList("linux", "windows"),
                Arrays.asList("xdr", "siem"));
    }

    public void testToMapAndFromMapRoundTrip() {
        RuleMetadata original = populated();
        Map<String, Object> serialized = original.toMap();
        RuleMetadata restored = RuleMetadata.fromMap(serialized);

        Assert.assertEquals(original.getTitle(), restored.getTitle());
        Assert.assertEquals(original.getAuthor(), restored.getAuthor());
        Assert.assertEquals(original.getDate(), restored.getDate());
        Assert.assertEquals(original.getModified(), restored.getModified());
        Assert.assertEquals(original.getDescription(), restored.getDescription());
        Assert.assertEquals(original.getReferences(), restored.getReferences());
        Assert.assertEquals(original.getDocumentation(), restored.getDocumentation());
        Assert.assertEquals(original.getModule(), restored.getModule());
        Assert.assertEquals(original.getVersions(), restored.getVersions());
        Assert.assertEquals(original.getCompatibility(), restored.getCompatibility());
        Assert.assertEquals(original.getSupports(), restored.getSupports());
    }

    public void testToMapOmitsNullAndEmpty() {
        RuleMetadata empty = RuleMetadata.empty();
        Assert.assertTrue(empty.isEmpty());
        Assert.assertTrue(empty.toMap().isEmpty());
    }

    public void testFromMapWithNullReturnsEmpty() {
        RuleMetadata fromNull = RuleMetadata.fromMap(null);
        Assert.assertTrue(fromNull.isEmpty());
        Assert.assertNull(fromNull.getTitle());
        Assert.assertEquals(List.of(), fromNull.getReferences());
    }

    public void testFromMapIgnoresNonListEntriesForListFields() {
        Map<String, Object> map = new HashMap<>();
        map.put(RuleMetadata.TITLE, "T");
        map.put(RuleMetadata.REFERENCES, "not-a-list");
        map.put(RuleMetadata.VERSIONS, 42);

        RuleMetadata m = RuleMetadata.fromMap(map);
        Assert.assertEquals("T", m.getTitle());
        Assert.assertEquals(List.of(), m.getReferences());
        Assert.assertEquals(List.of(), m.getVersions());
    }

    public void testStreamRoundTrip() throws IOException {
        RuleMetadata original = populated();
        BytesStreamOutput out = new BytesStreamOutput();
        original.writeTo(out);

        StreamInput in = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        RuleMetadata restored = RuleMetadata.readFrom(in);

        Assert.assertEquals(original.toMap(), restored.toMap());
    }

    public void testStreamRoundTripEmpty() throws IOException {
        RuleMetadata original = RuleMetadata.empty();
        BytesStreamOutput out = new BytesStreamOutput();
        original.writeTo(out);

        StreamInput in = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        RuleMetadata restored = RuleMetadata.readFrom(in);

        Assert.assertTrue(restored.isEmpty());
    }

    public void testXContentRoundTrip() throws IOException {
        RuleMetadata original = populated();
        XContentBuilder builder = XContentFactory.jsonBuilder();
        original.toXContent(builder, ToXContent.EMPTY_PARAMS);

        XContentParser parser =
                XContentType.JSON
                        .xContent()
                        .createParser(
                                NamedXContentRegistry.EMPTY,
                                LoggingDeprecationHandler.INSTANCE,
                                builder.toString());
        parser.nextToken();
        RuleMetadata restored = RuleMetadata.parse(parser);

        Assert.assertEquals(original.toMap(), restored.toMap());
    }
}
