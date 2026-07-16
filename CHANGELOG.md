## [v5.0.0]

### Added
- Init repository [(#1)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/1)
- Implement GH Action for Local Maven publication [(#743)](https://github.com/wazuh/wazuh-indexer-plugins/issues/743)
- Add Unclassified log category for integrations and custom log types [(#832)](https://github.com/wazuh/wazuh-indexer-plugins/issues/832)
- Implement finding enrichment [(#57)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/57)
- Implement extended sigma rules syntax [(#47)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/47)
- Modify rule and log type creation logic to enable them to have a lifecycle support [(#37)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/37)
- Implement spotless configuration from Wazuh Indexer Plugins repository [(#60)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/60)
- Add logs to detect problems with detectors creation [(#39)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/39)
- Create new Rule Testing action [(#56)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/56)
- Add --set-as-main flag support to repository bumper [(#88)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/88)
- Add Wazuh Alerting plugin to the build process [(#1)](https://github.com/wazuh/wazuh-indexer-alerting/issues/1)
- Validate single rule space per detector [(#117)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/117)
- Add revert bump functionality to repository bumper workflow [(#145)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/145)
- Add dynamic interpolation of rule fields [(#181)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/181)
- Add Exists Sigma Modifier [(#173)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/173)
- Add support for case-insensitive Sigma operators [(#182)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/182)
- Restrict thread detectors sources to wazuh-events-v5 [(#208)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/208)
- Add new Transport action to delete space resources [(#973)](https://github.com/wazuh/wazuh-indexer-plugins/issues/973)
- Add support for dynamic configuration of threat detectors [(#1029)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1029)
- Add endpoint to update findings [(#1220)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1220)
- Add limits for the creation of rules per thread detectors [(#1276)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1276)
- Support new findings case management fields [(#1334)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1334)
- Create new Action to toggle enabled/disable detectors [(#1356)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1356)

### Changed
- Update to JDK 25 [(#1341)](https://github.com/wazuh/wazuh-indexer/issues/1341)
- Change SAP logic to use findings indices [(#72)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/72)
- Limit number of rules per detector [(#111)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/111)
- Prevent modification of standard threat detectors [(#112)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/112)
- Remove duplicated metadata fields for rules [(#147)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/147)
- Normalize space values to lowercase across SAP [(#146)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/146)
- Improve time correlation between events and findings [(#214)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/214)
- Nest `rule` under `wazuh` object [(#1121)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1121)
- Remove unused settings [(#219)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/219)

### Removed
- Disable Rules and Log Types actions [(#38)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/38)

### Fixed
- Fix typo in revision variable [(#1194)](https://github.com/wazuh/wazuh-indexer/issues/1194)
- Fix link-checker workflow [(#867)](https://github.com/wazuh/wazuh-indexer-plugins/issues/867)
- Fix CodeQL auto-build failure using manual compilation [(#61)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/61)
- Fix detector creation to query custom rules by `document.id`[(#97)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/97)
- Fix race condition on findings' correlation [(#82)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/82)
- Fix CodeQL issues [(#110)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/110)
- Fix stale detector references after rule deletion [(#1043)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1043)
- Fix race condition and missing else branch on correlation metadata index creation [(#148)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/148)
- Fix contains conditions using white spaces [(#127)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/127)
- Fix enrichment dispatch coupling that dropped findings on correlation failure [(#168)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/168)
- Fix `ClassCastException` in `WTransportDeleteSpaceResourcesAction` [(#1150)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1150)

## Prior versions
- []()
