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

### Dependencies
-

### Changed
- Rename folder for pre-packaged rules [(#10)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/10)
- Build SAP in Content Manager workflow [(#17)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/17)
- Skip validation of Integrations source [(#20)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/20)
- Merge `cloud-services` categories [(#19)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/19)
- Create Integrations and Detectors using CTI IDs [(#21)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/21)
- Load Wazuh Integrations and Rules as standard [(#23)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/23)
- Improve logging of security-analytics resources [(#24)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/24)

### Deprecated
-

### Removed
- Disable pre-packaged rules [(#9)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/9)
- Remove Job Scheduler and IOCs stuff from the plugin [(#12)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/12)

### Fixed
- Fix typo in revision variable [(#4)](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/4)

### Security
-

[Unreleased 5.0.x]: https://github.com/wazuh/wazuh-indexer-security-analytics/compare/main...main
