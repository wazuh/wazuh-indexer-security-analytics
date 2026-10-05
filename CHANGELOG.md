## [v5.0.0]

### Added
- Compatibility with OpenSearch 3.6.0 [(#103)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/103)
- Add standard threat detectors, created and configured from CTI for every Wazuh integration [(#112)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/112) [(#1029)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1029) [(#1356)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1356) [(#1403)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1403)
- Add lifecycle spaces (`draft`, `test`, `custom`, `standard`) for rules and integrations [(#37)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/37) [(#812)](https://github.com/wazuh/wazuh-indexer-plugins/issues/812)
- Add enriched, WCS-compliant findings to the `wazuh-findings-v5-<category>` data streams [(#57)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/57) [(#72)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/72) [(#1121)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1121) [(#214)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/214)
- Add MITRE ATT&CK tactic, technique and sub-technique fields to findings [(#1208)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1208)
- Add dynamic rule fields in findings [(#181)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/181)
- Add findings case management [(#1220)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1220) [(#1334)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1334)
- Add rule testing capabilities in logtest [(#56)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/56)
- Add WCS validation for Sigma rule fields [(#47)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/47)
- Add the Sigma `exists` modifier [(#173)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/173)
- Add the `unclassified` log category [(#832)](https://github.com/wazuh/wazuh-indexer-plugins/issues/832)
- Add settings to limit the number of detectors and the rules per detector [(#111)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/111) [(#1276)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1276) [(#1420)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1420)
- Add settings to tune findings enrichment and correlation under load [(#244)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/244) [(#1683)](https://github.com/wazuh/wazuh-indexer/issues/1683)
- Add a log entry when a threat detector is enabled or disabled [(#1531)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1531)

- Initialize `wazuh-indexer-security-analytics` repository [(#1)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/1)

- (operational) Add a GitHub Action to publish Security Analytics and its commons library to the local Maven repository [(#743)](https://github.com/wazuh/wazuh-indexer-plugins/issues/743)
- (operational) Add Spotless formatting checks and a pre-commit hook [(#60)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/60)
- (operational) Add the `--set-as-main` flag to the repository bumper [(#88)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/88)
- (operational) Add revert support to the repository bumper workflow [(#145)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/145) [(#234)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/234)
- (operational) Add reporting of skipped bumps to the repository bumper workflow [(#291)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/291)

### Changed
- Replace OpenSearch alerting and common-utils with their Wazuh indexer forks [(#1)](https://github.com/wazuh/wazuh-indexer-alerting/issues/1) [(#1)](https://github.com/wazuh/wazuh-indexer-common-utils/issues/1)
- Reject threat detectors that mix `standard` and `custom` rules or use rules not yet promoted from `draft` or `test` [(#39)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/39) [(#117)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/117)
- Restrict threat detector data sources to `wazuh-events-v5*` [(#208)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/208)
- Change the `rule` field of the rules indices from `nested` to `object` [(#1214)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1214)

- (operational) Upgrade the CI workflows to JDK 25 [(#1341)](https://github.com/wazuh/wazuh-indexer/issues/1341)
- (operational) Upgrade the GitHub Actions to Node.js 24 [(#1368)](https://github.com/wazuh/wazuh-indexer/issues/1368)
- (operational) Publish the plugin zip to the local Maven repository under the `com.wazuh` group [(#1439)](https://github.com/wazuh/wazuh-indexer/issues/1439)
- (operational) Share build artifacts between workflow jobs through the Maven cache [(#1443)](https://github.com/wazuh/wazuh-indexer/issues/1443)
- (operational) Resolve the plugin build version from `VERSION.json` [(#1595)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1595)
- (operational) Migrate the workflows to AWS runners [(#236)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/236)
- (operational) Skip the pull request workflows while the pull request is a draft [(#228)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/228)
- (operational) Update CodeQL configuration [(#61)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/61) [(#110)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/110) [(#1497)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1497)

### Removed
- Remove the Threat Intelligence (IOC) feature, its REST endpoints and settings [(#12)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/12) [(#219)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/219)
- Remove the upstream pre-packaged Sigma rules and log types [(#9)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/9)
- Remove the rule and log type management REST endpoints [(#38)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/38)

### Fixed
- Fix Sigma rules never matching values that contain spaces [(#127)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/127) [(#285)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/285) [(#1529)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1529)
- Fix rules with a negated filter never firing on events that lack the filtered field [(#1518)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1518) [(#1527)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1527)
- Fix Sigma `|re` anchors and `|gt`/`|gte`/`|lt`/`|lte` modifiers never matching [(#335)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/335)
- Fix Sigma conditions not recognizing uppercase `AND`, `OR` and `NOT` [(#182)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/182)
- Fix findings skipping correlation while the correlation indices are being created [(#82)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/82) [(#148)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/148)
- Fix detectors being lost when several are created at the same time [(#1914)](https://github.com/wazuh/wazuh-indexer/issues/1914)
- Fix errors logged by correlation and detector deletion right after startup [(#1730)](https://github.com/wazuh/wazuh-indexer/issues/1730)
- Fix duplicated log type initialization errors at node startup [(#282)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/282)
- Fix malformed detector and correlation rule requests returning HTTP 500 before the permission check [(#312)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/312)
- Fix ANTLR version mismatch warnings logged at startup [(#1583)](https://github.com/wazuh/wazuh-indexer/issues/1583)
- Fix Sigma rule conversion errors and invalid CIDR prefixes not being reported [(#313)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/313)

- (operational) Fix the package generation workflow ignoring the requested revision [(#1194)](https://github.com/wazuh/wazuh-indexer/issues/1194)
- (operational) Fix package generation failing in the alerting publication stage [(#1430)](https://github.com/wazuh/wazuh-indexer/issues/1430)
- (operational) Fix `linkchecker` workflow failures [(#867)](https://github.com/wazuh/wazuh-indexer-plugins/issues/867)
- (operational) Fix the repository bumper `tag` input defaulting to `true` [(#1765)](https://github.com/wazuh/wazuh-indexer/issues/1765)

## Prior versions
- []()
