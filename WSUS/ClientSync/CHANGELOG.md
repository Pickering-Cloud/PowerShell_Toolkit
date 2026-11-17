# Changelog

All notable changes to this script are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and version numbers follow [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-17

### Added

- Optional update check. Reads a static version file from `https://pickering.cloud/tools/versions.json` and logs a notice when a newer version is available. Nothing is sent, nothing is downloaded or installed, and only an interactive session is offered the chance to open the GitHub release page. Remote and unattended sessions, and `-WhatIf`, never prompt.
- Optional anonymous usage telemetry (tool, version, OS and build, PowerShell version and edition, timezone, run mode). No server names, machine names, update or error details are sent. See `TELEMETRY.md` in the repository root.
- `-DisableUpdateCheck` and `-DisableTelemetry` switches, which work independently of each other.
- `PICKERINGCLOUD_NOTELEMETRY` environment variable (`1` or `true`) to disable telemetry across every tool in the toolkit.
- README sections for the update check and telemetry, exit codes, and `-WhatIf`.

### Changed

- The main script body now runs inside `try`/`finally` so the update check and telemetry run on every exit path, including the Critical-level exits.
- Script header help documents the new parameters and the update check and telemetry behaviour.

### Fixed

- `-CustomLogPath` was documented but not implemented in the parameter block. It is now a working parameter.
- README and script help gave a default log path (`C:\tmp\WSUS\WSUS-ClientSync.log`) that did not match the script. Both now show `C:\Pickering-Cloud\Logs\WSUS-Client\WSUS-ClientSync.log`.

## [1.0.0] - Initial release

### Added

- Initial release.
- Read-only-protected log file with configurable level (Debug through Critical, or None), interactive prompt for local sessions, automatic Info default for remote/unattended sessions.
- Application Event Log integration under source "WSUS Client Sync Script", with a documented, unique event ID per condition (see README).
- Collection of the currently configured WSUS server/status server from Group Policy, with a forced `gpupdate` and re-check for policy drift.
- Configuration testing: DNS resolution, network reachability (ping and port), and HTTPS certificate trust validation (skipped cleanly if WSUS isn't using SSL).
- Prerequisite checks: pending reboot (component servicing, Windows Update, pending rename, SCCM client), free disk space on the system drive, and disabled/stopped prerequisite services.
- Synchronisation attempts via Windows Update Agent COM API, `UsoClient`, and legacy `wuauclt`, with configurable retry count and success detection via `LastSuccessTime`.
- Update history review, scoped to errors that occurred since the script started, avoiding stale historical noise.
- `-AutomaticallyRemediate` switch enabling automatic fixes for recognised error codes, using a shared library of idempotent repair actions (SFC, DISM, SoftwareDistribution/catroot2 reset, BITS queue reset with file-level fallback).
- Deliberate non-remediation of policy-managed misconfigurations (malformed WSUS URL, Windows Update disabled by policy), logged with guidance rather than auto-corrected.
- Post-remediation synchronisation retry, gated to only run when the initial attempt failed and remediation was actually attempted.