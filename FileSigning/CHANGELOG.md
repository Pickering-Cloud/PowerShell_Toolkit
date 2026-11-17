# Changelog

All notable changes to this script are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and version numbers follow [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-17

### Added
- Optional update check against a static version file, with a notice (and an interactive-only offer to open the release page). Disable with `-DisableUpdateCheck`.
- Optional anonymous usage telemetry. Disable with `-DisableTelemetry` or `PICKERINGCLOUD_NOTELEMETRY=1`. Independent of the update check.

### Fixed
- README: restored backslashes in `.\SignFileConfig.json` and `Cert:\LocalMachine\My`, and corrected the exit codes table formatting.

## [1.0.0] - Initial release

### Added
- Initial release.
- Existing certificate detection in the configured store (`LocalMachine\My` or `CurrentUser\My`).
- ADCS certificate request via default AD-integrated enrollment, with availability check and Pending-request retry handling.
- Self-signed certificate fallback with automatic Trusted Root / Trusted Publisher installation.
- `-RequireADCSCertificate` to disable the self-signed fallback.
- Interactive multi-select file picker with PowerShell-signable and general Authenticode-signable filters, alongside single-file `-Path` for command-line use.
- Optional RFC 3161 timestamping via `-TimestampingAuthority`.
- JSON config file support with IT-governed precedence over command-line parameters.
- `-BuildConfig` to generate a template config file from current parameter values.