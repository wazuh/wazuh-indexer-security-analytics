## [v5.0.0]

### Added

| Issue | Comment |
|-------|---------|
| [#1](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/1) | Initialize `wazuh-indexer-security-analytics` repository |
| [#103](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/103) | Compatibility with OpenSearch 3.6.0 |
| [#112](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/112) [#1029](https://github.com/wazuh/wazuh-indexer-plugins/issues/1029) [#1356](https://github.com/wazuh/wazuh-indexer-plugins/issues/1356) [#1403](https://github.com/wazuh/wazuh-indexer-plugins/issues/1403) | Add standard threat detectors, created and configured from CTI for every Wazuh integration |
| [#37](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/37) [#812](https://github.com/wazuh/wazuh-indexer-plugins/issues/812) [#39](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/39) [#117](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/117)| Add lifecycle spaces (`draft`, `test`, `custom`, `standard`) for rules and integrations |
| [#57](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/57) [#72](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/72) [#1121](https://github.com/wazuh/wazuh-indexer-plugins/issues/1121) [#214](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/214) [#1208](https://github.com/wazuh/wazuh-indexer-plugins/issues/1208)| Add enriched, WCS-compliant findings to the `wazuh-findings-v5-<category>` data streams |
| [#181](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/181) | Add dynamic rule fields in findings |
| [#1220](https://github.com/wazuh/wazuh-indexer-plugins/issues/1220) [#1334](https://github.com/wazuh/wazuh-indexer-plugins/issues/1334) | Add findings case management |
| [#56](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/56) | Add rule testing capabilities in logtest |
| [#47](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/47) | Add WCS validation for Sigma rule fields |
| [#173](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/173) | Add the Sigma `exists` modifier |
| [#832](https://github.com/wazuh/wazuh-indexer-plugins/issues/832) | Add the `unclassified` log category |
| [#111](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/111) [#1276](https://github.com/wazuh/wazuh-indexer-plugins/issues/1276) [#1420](https://github.com/wazuh/wazuh-indexer-plugins/issues/1420) | Add settings to limit the number of detectors and the rules per detector |
| [#244](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/244) [#1683](https://github.com/wazuh/wazuh-indexer/issues/1683) | Add settings to tune findings enrichment and correlation under load |
| [#1531](https://github.com/wazuh/wazuh-indexer-plugins/issues/1531) | Add a log entry when a threat detector is enabled or disabled |

### Changed

| Issue | Comment |
|-------|---------|
| [#208](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/208) | Restrict threat detector data sources to `wazuh-events-v5*` |
| [#1214](https://github.com/wazuh/wazuh-indexer-plugins/issues/1214) | Change the `rule` field of the rules indices from `nested` to `object` |

### Removed

| Issue | Comment |
|-------|---------|
| [#219](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/219) | Remove the Threat Intelligence (IOC) feature, its REST endpoints and settings |
| [#38](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/38) | Remove the rule and log type management REST endpoints |

### Fixed

| Issue | Comment |
|-------|---------|
| [#127](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/127) [#285](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/285) [#1529](https://github.com/wazuh/wazuh-indexer-plugins/issues/1529) | Fix Sigma rules never matching values that contain spaces |
| [#1518](https://github.com/wazuh/wazuh-indexer-plugins/issues/1518) [#1527](https://github.com/wazuh/wazuh-indexer-plugins/issues/1527) | Fix rules with a negated filter never firing on events that lack the filtered field |
| [#335](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/335) | Fix Sigma `\|re` anchors and `\|gt`/`\|gte`/`\|lt`/`\|lte` modifiers never matching |
| [#182](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/182) | Fix Sigma conditions not recognizing uppercase `AND`, `OR` and `NOT` |
| [#82](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/82) [#148](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/148) | Fix findings skipping correlation while the correlation indices are being created |
| [#1730](https://github.com/wazuh/wazuh-indexer/issues/1730) | Fix errors logged by correlation and detector deletion right after startup |
| [#282](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/282) | Fix duplicated log type initialization errors at node startup |
| [#1583](https://github.com/wazuh/wazuh-indexer/issues/1583) | Fix ANTLR version mismatch warnings logged at startup |
| [#313](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/313) | Fix Sigma rule conversion errors and invalid CIDR prefixes not being reported |

## Prior versions
