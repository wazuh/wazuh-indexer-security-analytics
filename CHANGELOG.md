# CHANGELOG
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 5.0.x]
### Added
- Init repository [(#2)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/2)
- Add initial version of SAP commons lib [(#13)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/13/)
- Add transport classes to the "commons" lib to create integrations [(#14)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/14)
- Initialize threat detectors [(#15)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/15)
- Fix integrations not being created under the correct category [(#18)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/18)
- Add new actions to security-analytics-commons [(#22)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/22)
- Implement GH Action for Local Maven publication [(#29)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/29)
- Add new action to create custom rules [(#31)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/31)
- Add Unclassified log category for integrations and custom log types [(#42)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/42)
- Implement finding enrichment [(#58)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/58)
- Implement extended sigma rules sintax [(#55)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/55)
- Modify rule and log type creation logic to enable them to have a lifecycle support [(#69)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/69)
- Implement spotless configuration from Wazuh Indexer Plugins repository [(#70)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/70)
- Add logs to detect problems with detectors creation [(#83)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/83)
- Create new Rule Testing action [(#96)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/96)
- Add --set-as-main flag support to repository bumper [(#90)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/90)
- Add Wazuh Alerting plugin to the build process [(#114)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/114)
- Validate single rule space per detector [(#130)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/130)
- Add revert bump functionality to repository bumper workflow [(#154)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/154)
- Add Exists Sigma Modifier [(#185)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/185)
- Add support for case-insensitive Sigma operators [(#183)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/183)

### Dependencies
- Update to JDK 25 [(#49)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/49)

### Changed
- Rename folder for pre-packaged rules [(#10)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/10)
- Build SAP in Content Manager workflow [(#17)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/17)
- Skip validation of Integrations source [(#20)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/20)
- Merge `cloud-services` categories [(#19)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/19)
- Create Integrations and Detectors using CTI IDs [(#21)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/21)
- Load Wazuh Integrations and Rules as standard [(#23)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/23)
- Improve logging of security-analytics resources [(#24)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/24)
- Improve SAP code quality [(#26)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/26)
- Rename commons library [(#28)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/28)
- Allow creating custom and standard integrations [(#32)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/32)
- Change SAP logic to use findings indices [(#76)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/76)
- Optimize findings enrichment [(#93)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/93)
- Limit number of rules per detector [(#111)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/111)
- Disable standard threat detectors modification [(#121)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/121)
- Remove duplicated metadata fields for rules [(#163)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/163)
- Normalize space values to lowercase across SAP [(#174)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/174)

### Deprecated
-

### Removed
- Disable pre-packaged rules [(#9)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/9)
- Remove Job Scheduler and IOCs stuff from the plugin [(#12)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/12)

### Fixed
- Fix typo in revision variable [(#4)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/4)
- Fix link-checker workflow [(#50)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/50)
- Fix CodeQL autobuild failure using manual compilation [(#71)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/71)
- Fix detector creation to query custom rules by `document.id`[(#97)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/97)
- Fix race condition on findings correlation [(#106)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/106) [(#132)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/132)
- Fix codeql issues [(#113)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/113)
- Fix stale detector references after rule deletion [(#152)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/152)
- Fix race condition and missing else branch on correlation metadata index creation [(#148)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/184)
- Fix contains conditions using white spaces [(#162)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/162)

### Security
-

[Unreleased 5.0.x]: https://github.com/wazuh/wazuh-indexer-security-analytics/compare/1435464d84e284d514817616c3b957228f1c5518...main
