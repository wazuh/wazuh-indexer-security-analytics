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
package org.opensearch.securityanalytics.correlation.index.query;

import org.apache.lucene.search.KnnFloatVectorQuery;
import org.apache.lucene.search.Query;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryShardContext;

import java.io.IOException;
import java.util.Optional;

public class CorrelationQueryFactory {

    public static Query create(CreateQueryRequest createQueryRequest) {
        final String fieldName = createQueryRequest.getFieldName();
        final int k = createQueryRequest.getK();
        final float[] vector = createQueryRequest.getVector();

        if (createQueryRequest.getFilter().isPresent()) {
            final QueryShardContext context =
                    createQueryRequest
                            .getContext()
                            .orElseThrow(() -> new RuntimeException("Shard context cannot be null"));

            try {
                final Query filterQuery = createQueryRequest.getFilter().get().toQuery(context);
                return new KnnFloatVectorQuery(fieldName, vector, k, filterQuery);
            } catch (IOException ex) {
                throw new RuntimeException("Cannot create knn query with filter", ex);
            }
        }
        return new KnnFloatVectorQuery(fieldName, vector, k);
    }

    static class CreateQueryRequest {
        private String fieldName;

        private float[] vector;

        private int k;

        private QueryBuilder filter;

        private QueryShardContext context;

        public CreateQueryRequest(
                String fieldName, float[] vector, int k, QueryBuilder filter, QueryShardContext context) {
            this.fieldName = fieldName;
            this.vector = vector;
            this.k = k;
            this.filter = filter;
            this.context = context;
        }

        public String getFieldName() {
            return fieldName;
        }

        public float[] getVector() {
            return vector;
        }

        public int getK() {
            return k;
        }

        public Optional<QueryBuilder> getFilter() {
            return Optional.ofNullable(filter);
        }

        public Optional<QueryShardContext> getContext() {
            return Optional.ofNullable(context);
        }
    }
}
