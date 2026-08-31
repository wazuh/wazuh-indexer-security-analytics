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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.transport.client.Client;

import java.util.Map;

/**
 * Records a user's Start/Stop of a standard detector in the Content Manager user-overrides
 * registry, so it survives the next rebuild of the standard space.
 *
 * <p>Content Manager cannot be called from here — it declares this plugin in {@code
 * extendedPlugins}, so the dependency only runs one way — but the registry is data, and the
 * policies index is a regular index. One partial update is enough.
 *
 * <p>Only user-driven REST updates reach this. Content Manager pushes detector state through {@code
 * WIndexDetectorAction} and {@code WSetDetectorEnabledAction}, which are separate action types
 * registered separately from {@code IndexDetectorAction}, so its own writes can never come back
 * here and the write-back loop is impossible by construction rather than by a guard.
 */
public final class RegistryOverrideWriter {

    private static final Logger log = LogManager.getLogger(RegistryOverrideWriter.class);

    /**
     * Content Manager's policies index and the reserved id of its registry document. Duplicated from
     * {@code com.wazuh.contentmanager.utils.Constants} — see {@code KEY_USER_OVERRIDES} and {@code
     * USER_OVERRIDES_DOC_ID} there — because the dependency between the two plugins only runs the
     * other way. Keep both sides in step.
     */
    private static final String POLICIES_INDEX = "wazuh-threatintel-policies";

    private static final String USER_OVERRIDES_DOC_ID = "wazuh-user-overrides";
    private static final String USER_OVERRIDES = "user_overrides";
    private static final String STANDARD_SPACE = "standard";
    private static final String INTEGRATIONS = "integrations";
    private static final String DETECTOR_ENABLED = "detector_enabled";

    private RegistryOverrideWriter() {}

    /**
     * Records the detector's enabled state, if it is one Content Manager owns.
     *
     * <p>A failure is logged and swallowed: the detector update itself has already succeeded, so
     * failing the request here would be a lie. The cost is that this decision will not survive the
     * next rebuild of the standard space.
     *
     * @param client used to write the registry document.
     * @param detectorId the detector's id, which is also its integration's id.
     * @param detector the detector as the user just saved it.
     */
    public static void recordDetectorEnabled(Client client, String detectorId, Detector detector) {
        if (detector == null || !detector.isStandardDetector()) {
            // A detector the user created in Security Analytics has no integration behind it, so an
            // override keyed by its id would name something that does not exist.
            return;
        }

        // A partial `doc` update merges objects recursively, so the other integrations' entries and the
        // policy and filters sections are untouched. That is why Content Manager keys this section by
        // id instead of using an array, which a merge would replace wholesale. `docAsUpsert` covers the
        // first write, when the registry does not exist yet; the document it creates carries no `space`
        // field, which is what keeps it out of the pre-snapshot wipe.
        UpdateRequest request =
                new UpdateRequest(POLICIES_INDEX, USER_OVERRIDES_DOC_ID)
                        .doc(
                                Map.of(
                                        USER_OVERRIDES,
                                        Map.of(
                                                STANDARD_SPACE,
                                                Map.of(
                                                        INTEGRATIONS,
                                                        Map.of(detectorId, Map.of(DETECTOR_ENABLED, detector.getEnabled()))))))
                        .docAsUpsert(true)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        client.update(
                request,
                ActionListener.wrap(
                        response ->
                                log.debug(
                                        "Recorded detector [{}] enabled={} in the user overrides registry",
                                        detectorId,
                                        detector.getEnabled()),
                        e ->
                                log.warn(
                                        "Failed to record detector [{}] in the user overrides registry. The detector"
                                                + " itself is fine, but this choice will not survive the next content"
                                                + " rebuild of the standard space: {}",
                                        detectorId,
                                        e.getMessage())));
    }
}
