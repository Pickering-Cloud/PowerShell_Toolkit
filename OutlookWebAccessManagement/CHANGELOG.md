# Changelog

All notable changes to Manage-OWA are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-17

### Added

- Optional update check. Reads a static version file from `https://pickering.cloud/tools/versions.json` and tells you when a newer version is available. Nothing is sent, nothing is downloaded or installed, and an interactive session is only offered the chance to open the GitHub release page. Unattended runs never prompt.
- Optional anonymous usage telemetry (tool, version, OS and build, PowerShell version and edition, timezone, run mode). No tenant, user, mailbox or licence data is sent. See `TELEMETRY.md` in the repository root.
- `-DisableUpdateCheck` and `-DisableTelemetry` switches, which work independently of each other.
- `PICKERINGCLOUD_NOTELEMETRY` environment variable (`1` or `true`) to disable telemetry across every tool in the toolkit.
- `[CmdletBinding()]`, enabling `-Verbose`, which prints the exact telemetry payload.
- `README.md` and `CHANGELOG.md`.

### Changed

- The main script body now runs inside `try`/`finally` so the update check and telemetry run on every exit path, including CRITICAL errors.
- Script header help documents the new parameters and the update check and telemetry behaviour.

## [1.0.0] - Initial release

### Added

- Blocks Outlook client access (`OWAEnabled`, `OWAforDevicesEnabled`, `OutlookMobileEnabled`, `MacOutlookEnabled`, `OneWinNativeOutlookEnabled`) for users licensed with Microsoft 365 F1 or Office 365 F1.
- Blocks mailbox holders with no licence that grants Exchange Online, using a configurable list of mailbox-granting SKU part numbers.
- Automatically unblocks users who are no longer in scope, for example after a licence upgrade. Failed unblocks are retried on the next run.
- Persistent state file (`BlockedUsers.psd1`) tracking currently blocked users, with the date and reason.
- Dated CSV report of every block and unblock action.
- Dated log file with INFO, WARN, ERROR and CRITICAL levels. CRITICAL exits with code 1.
- `-Setup` switch for interactive, one-off service principal provisioning: certificate, app registration, Graph application permissions (`User.Read.All`, `Organization.Read.All`), `Exchange.ManageAsApp` and the Exchange Administrator directory role.
- Certificate-based app-only authentication to Microsoft Graph and Exchange Online for unattended use.
- `config.psd1` for tenant ID, client ID and certificate thumbprint, created automatically on first run and updated by `-Setup`.
- Automatic installation of missing PowerShell modules for the current user.
- Progress bars for the block and unblock passes.