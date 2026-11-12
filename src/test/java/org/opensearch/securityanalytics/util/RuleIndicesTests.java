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
package org.opensearch.securityanalytics.util;

import org.apache.lucene.tests.mockfile.LeakFS;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.mockito.Mockito.mock;

/**
 * Loading the rules shipped on disk lists the rules directory and every directory under it. Each
 * listing holds its directory open until it is closed, so these tests run the loading over a file
 * system that keeps track of what is open and check that nothing is left behind.
 */
public class RuleIndicesTests extends OpenSearchTestCase {

    /** File system that fails {@link LeakFS#onClose()} while any of its handles is still open. */
    private LeakFS openHandles;

    /** Rules directory: one category holding a rule and a nested directory with another rule. */
    private Path rulesDir;

    private RuleIndices ruleIndices;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        Path dir = createTempDir();
        Path category = Files.createDirectories(dir.resolve("network"));
        Files.writeString(category.resolve("first.yml"), "title: first");
        Path nested = Files.createDirectories(category.resolve("nested"));
        Files.writeString(nested.resolve("second.yml"), "title: second");

        this.openHandles = new LeakFS(dir.getFileSystem());
        this.rulesDir = this.openHandles.wrapPath(dir);
        this.ruleIndices =
                new RuleIndices(
                        mock(LogTypeService.class),
                        mock(Client.class),
                        mock(ClusterService.class),
                        mock(ThreadPool.class));
    }

    private Object invoke(String method, Class<?>[] parameterTypes, Object... arguments)
            throws Exception {
        Method target = RuleIndices.class.getDeclaredMethod(method, parameterTypes);
        target.setAccessible(true);
        return target.invoke(this.ruleIndices, arguments);
    }

    @SuppressWarnings("unchecked")
    public void testGetRules_closesEveryDirectoryItLists() throws Exception {
        List<String> rules =
                (List<String>) invoke("getRules", new Class<?>[] {List.class}, List.of(this.rulesDir));

        assertEquals(2, rules.size());
        assertTrue(rules.containsAll(List.of("title: first", "title: second")));
        this.openHandles.onClose();
    }

    @SuppressWarnings("unchecked")
    public void testLoadQueries_closesTheRulesDirectory() throws Exception {
        invoke(
                "loadQueries",
                new Class<?>[] {
                    Path.class, WriteRequest.RefreshPolicy.class, TimeValue.class, ActionListener.class
                },
                this.rulesDir,
                WriteRequest.RefreshPolicy.IMMEDIATE,
                TimeValue.timeValueSeconds(60),
                (ActionListener<BulkResponse>) mock(ActionListener.class));

        this.openHandles.onClose();
    }
}
