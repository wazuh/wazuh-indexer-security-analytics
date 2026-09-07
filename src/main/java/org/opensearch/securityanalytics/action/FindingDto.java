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

import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.FindingDocument;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

public class FindingDto implements ToXContentObject, Writeable {

    private static final String DETECTOR_ID_FIELD = "detectorId";
    private static final String FINDING_ID_FIELD = "id";
    private static final String RELATED_DOC_IDS_FIELD = "related_doc_ids";
    private static final String INDEX_FIELD = "index";
    private static final String QUERIES_FIELD = "queries";
    private static final String TIMESTAMP_FIELD = "timestamp";
    private static final String DOCUMENTS_LIST = "document_list";

    private String id;
    private List<String> relatedDocIds;
    private String index;
    private List<DocLevelQuery> docLevelQueries;
    private Instant timestamp;
    private List<FindingDocument> documents;

    private String detectorId;

    public FindingDto(
            String detectorId,
            String id,
            List<String> relatedDocIds,
            String index,
            List<DocLevelQuery> docLevelQueries,
            Instant timestamp,
            List<FindingDocument> documents) {
        this.detectorId = detectorId;
        this.id = id;
        this.relatedDocIds = relatedDocIds;
        this.index = index;
        this.docLevelQueries = docLevelQueries;
        this.timestamp = timestamp;
        this.documents = documents;
    }

    public FindingDto(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readStringList(),
                sin.readString(),
                sin.readList(DocLevelQuery::readFrom),
                sin.readInstant(),
                sin.readList(FindingDocument::new));
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params)
            throws IOException {
        builder
                .startObject()
                .field(DETECTOR_ID_FIELD, detectorId)
                .field(FINDING_ID_FIELD, id)
                .field(RELATED_DOC_IDS_FIELD, relatedDocIds)
                .field(INDEX_FIELD, index)
                .field(QUERIES_FIELD, docLevelQueries)
                .field(TIMESTAMP_FIELD, timestamp.toEpochMilli())
                .field(DOCUMENTS_LIST, documents);
        builder.endObject();
        return builder;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        out.writeString(id);
        out.writeStringCollection(relatedDocIds);
        out.writeString(index);
        out.writeCollection(docLevelQueries);
        out.writeInstant(timestamp);
        out.writeList(documents);
    }

    public String getId() {
        return id;
    }

    public List<String> getRelatedDocIds() {
        return relatedDocIds;
    }

    public String getIndex() {
        return index;
    }

    public List<DocLevelQuery> getDocLevelQueries() {
        return docLevelQueries;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public List<FindingDocument> getDocuments() {
        return documents;
    }

    public String getDetectorId() {
        return detectorId;
    }
}
