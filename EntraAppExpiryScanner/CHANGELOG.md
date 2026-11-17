# Changelog

All notable changes to EntraAppExpiryScanner are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this tool adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-17

### Added

- Initial release.
- Scans Entra ID app registration secrets and certificates for expiry using Microsoft Graph REST.
- Severity bands (Expired, Critical, Warning, Notice) with configurable thresholds, defaulting to 7, 30 and 60 days.
- Reporting of app registrations with no owner and app registrations with no credentials.
- Interactive, certificate and client secret authentication.
- Timestamped HTML and CSV reports with summary tiles.
- Automatic installation of `Microsoft.Graph.Authentication` to the current user scope.
- File logging via `Write-LogFile` with a configurable level, defaulting to `C:\Pickering-Cloud\Logs\Entra\EntraAppExpiryScanner.log`.
- Application event log entries via `Write-LogEvent` under the source `EntraAppExpiryScanner`. Findings are logged as Information or Warning, and only a failed scan is logged as an Error.
- Report retention cleanup, defaulting to 30 days, with `-WhatIf` support.
- Exit code 0 for any completed scan and 1 for a failed scan.
- Optional update check against a static version file, with a notice (and an interactive-only offer to open the release page). Disable with `-DisableUpdateCheck`.
- Optional anonymous usage telemetry. Disable with `-DisableTelemetry` or `PICKERINGCLOUD_NOTELEMETRY=1`. Independent of the update check.