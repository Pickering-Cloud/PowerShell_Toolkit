# Changelog

All notable changes to `ADAccountAudit` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-08-22

### Added

- Initial release.
- Stale account detection based on `LastLogonTimestamp`, with configurable threshold via `-StaleDays`.
- Disabled-account-in-privileged-group detection, checking recursive/nested membership against a configurable group list via `-PrivilegedGroups`.
- Password expiry detection using `msDS-UserPasswordExpiryTimeComputed`, respecting fine-grained password policies, configurable via `-PasswordExpiryWarningDays`.
- Empty group detection, security groups by default with an opt-in `-IncludeDistributionGroups` switch to include distribution groups.
- `-SearchBase` parameter to scope all checks to a specific OU.
- HTML report with colour-coded findings and summary counts, plus a CSV export per finding category.
- Automatic log and report retention cleanup via `-LogRetentionDays` (default 30 days).
- Automatic installation of the ActiveDirectory (RSAT) module if not already present, with a clear manual-install message on failure.
- Designed for unattended Scheduled Task use: no interactive prompts, exit code 0/1 for success/failure.
- Read-only by design; performs no writes, disables, or membership changes against Active Directory.