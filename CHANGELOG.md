## [v5.0.0]

### Added
- Initialize `wazuh-indexer-security-analytics` repository [(#1)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/1)
- Publish Security Analytics to Maven using a custom GH Action [(#743)](https://github.com/wazuh/wazuh-indexer-plugins/issues/743)
- `wazuh-events-v5-unclassified` datastream [(#832)](https://github.com/wazuh/wazuh-indexer-plugins/issues/832)
- Findings enrichment [(#57)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/57)
- Extended Sigma rules syntax [(#47)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/47)
- Lifecycle space support for Log Types and Rules [(#37)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/37)
- Configure Spotless [(#60)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/60)
- Detector configuration constraints [(#39)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/39)
- Rule testing capabilities in logtest [(#56)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/56)
- Add `--set-as-main` flag support to repository bumper — `wazuh-indexer-security-analytics` [(#88)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/88)
- Initialize `wazuh-indexer-alerting` repository [(#1)](https://github.com/wazuh/wazuh-indexer-alerting/issues/1)
- Per-space threat detectors [(#117)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/117)
- Support Revert bump functionality in wazuh-indexer-security-analytics [(#145)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/145)
- Dynamic rule fields in findings [(#181)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/181)
- Missing Sigma modifiers [(#173)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/173)
- Case-insensitive Sigma operators [(#182)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/182)
- Restrict threat detectors sources [(#208)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/208)
- [BUG] Resources not removed in Security Analytics [(#973)](https://github.com/wazuh/wazuh-indexer-plugins/issues/973)
- Dynamic configuration of standard threat detectors [(#1029)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1029)
- Findings case management [(#1220)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1220)
- Configurable resource creation limits [(#1276)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1276)
- Findings case management pt.2 [(#1334)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1334)
- Integration's mode [(#1356)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1356)

### Changed
- Upgrade to JDK 25 [(#1341)](https://github.com/wazuh/wazuh-indexer/issues/1341)
- WCS compliant findings [(#72)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/72)
- Limited number of rules for detectors [(#111)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/111)
- Standard Threat Detectors [(#112)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/112)
- Remove duplicated metadata fields for rules [(#147)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/147)
- Normalize space values [(#146)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/146)
- Improve time correlation between events and findings [(#214)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/214)
- `rule` and `threat` fields alignment [(#1121)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1121)
- Undocumented plugin settings [(#219)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/219)

### Removed
- Content Management API updates [(#38)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/38)

### Fixed
- Failure while uploading artifacts in the package generation workflow [(#1194)](https://github.com/wazuh/wazuh-indexer/issues/1194)
- `linkchecker` failures [(#867)](https://github.com/wazuh/wazuh-indexer-plugins/issues/867)
- Failing CodeQL [(#61)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/61)
- [BUG] Detectors creation uses `_id` field [(#97)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/97)
- Missing findings [(#82)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/82)
- CodeQL failures [(#110)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/110)
- [BUG] Removed rules are still referenced in the threat detectors [(#1043)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1043)
- Race condition in correlation metadata index creation causes `ResourceAlreadyExistsException` [(#148)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/148)
- [BUG] Rules using `contains` and white spaces do not work [(#127)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/127)
- RCA: missing findings [(#168)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/168)
- ClassCastException during Security Analytics space resource deletion on startup [(#1150)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1150)

## Prior versions
- []()
