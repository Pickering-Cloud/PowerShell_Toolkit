# Pickering.Cloud PowerShell Toolkit

A collection of standalone PowerShell tools for Windows systems administration, each designed to run unattended and to be picked up and used by a single admin or small team without much ceremony.

## Structure

Each script lives in its own subfolder, with its own `README.MD` and `CHANGELOG.MD` documenting that script specifically. This keeps each script's documentation, configuration examples, and version history self-contained, so folders can be added, removed, or picked up independently without needing to understand the rest of the repository.

```
├── LICENSE
├── README.MD                  (this file)
├── .gitignore                 (repo-wide exclusions)
└── <ScriptName>/
   ├── <ScriptName>.ps1
   ├── README.MD               (usage, parameters, requirements)
   ├── CHANGELOG.MD            (version history for this script)
   ├── .gitignore               (script-specific exclusions, where needed)
   ├─── .env.EXAMPLE             (example environment file, where applicable)
   └── <ScriptName>.json.EXAMPLE (example config file, where applicable)
```

Each tool lives in its own folder with its own README covering setup, usage, and configuration in detail. This page is a quick-reference index - start here to find the right tool, then follow the link for full documentation.

## Tools

| Tool | What it does | Docs |
|:---|:---|:---:|
| **ADAccountAudit** | Read-only Active Directory report of stale accounts, disabled accounts still in privileged groups, passwords about to expire, and empty security groups. Writes an HTML report and CSV exports. | [ADAccountAudit/README.md](ActiveDirectoryManagement/ADAccountAudit/README.md) |
| **EntraAppExpiryScanner** | Read-only scan of every Entra ID app registration for expired or expiring secrets and certificates, apps with no owner, and apps with no credentials. Banded by severity, with an HTML report, CSV export and event log entries for monitoring. | [EntraAppExpiryScanner/README.md](EntraAppExpiryScanner/README.md) |
| **FileSigning** | Signs one or more files with a code signing certificate - uses an existing valid certificate if available, requests one from Active Directory Certificate Services (ADCS) if configured, or falls back to a self-signed certificate. Supports interactive file selection or a direct path, JSON-based policy configuration, and RFC 3161 timestamping. | [FileSigning/README.md](FileSigning/README.md) |
| **OutlookWebAccessManagement** | Queries an Entra tenant for users licensed with Microsoft 365 F1 / Office 365 F1, plus mailboxes with no licence granting Exchange access, and blocks Outlook client access (web, mobile, Mac, new Outlook) for both groups. Automatically restores access if a licence changes. Runs unattended via a certificate-based service principal. | [OutlookWebAccessManagement/README.md](OutlookWebAccessManagement/README.md) |
| **PSAnalyser** | Standalone linter, formatter and static security analyser for PowerShell scripts, in the spirit of ruff for Python. Formatting, lint, security (CWE-mapped) and 5.1/7 compatibility rules, safe automatic fixes with backups and diff previews, and CSV or JSON reports. Never runs the scripts it analyses. | [PSAnalyser/README.md](PSAnalyser/README.md) |
| **WSUS-ClientSync** | Forces a Windows client to check in against its configured WSUS server, runs diagnostics (DNS, reachability, certificate trust, pending reboot, disk space, disabled services), and optionally auto-remediates common synchronisation and installation errors. Designed to run across many machines via PowerShell remoting. | [WSUS-ClientSync/README.md](WSUS/ClientSync/README.md) |

## General conventions across these tools

- **Logs and reports** go to one predictable place per tool: `C:\ProgramData\PickeringCloud\<ToolName>\`. Each tool has a single appended log at `Logs\<ToolName>.log`, rotated at 10 MB with five older copies kept, and its reports in `Reports\`. Reports are named `<ToolName>_<timestamp>`, so retention cleanup only ever removes that tool's own files.
- **Standard parameters.** Every tool accepts the same set, on top of its own:

  | Parameter | Default | Description |
  |:---|:---|:---|
  | `-LogPath` | `C:\ProgramData\PickeringCloud\<ToolName>\Logs\<ToolName>.log` | Log file location. |
  | `-LoggingLevel` | `Info` | `Debug`, `Verbose`, `Info`, `Warn`, `Error`, `Critical` or `None` (or 1 to 7, with 0 also meaning `None`). `-Debug` and `-Verbose` raise it when this is not set. |
  | `-ReportPath` | `C:\ProgramData\PickeringCloud\<ToolName>\Reports` | Report folder, for tools that write reports. |
  | `-RetentionDays` | `30` | Reports older than this are removed. `0` disables cleanup. |
  | `-DisableUpdateCheck` | off | Skips the check for a newer version. |
  | `-DisableTelemetry` | off | Stops anonymous usage telemetry. |

- **Unattended runs never prompt.** A tool treats a run as unattended when it has no user session, input is redirected, or PowerShell was started with `-NonInteractive`. Use `-NonInteractive` in Scheduled Tasks to be certain.
- **Findings are results, not errors.** A tool exits `1` only when the run itself fails, not because it found something worth reporting.
- **Event log.** Tools write a small set of events to the Application log under their own source. Registering the source needs an elevated session once. Without it, the tool still runs and logs to file. Event log writes are not available in PowerShell 7.
- **Update check and telemetry.** After each run, a tool checks a static version file on `pickering.cloud` and sends anonymous usage telemetry. Neither affects the result of the run. See [TELEMETRY.md](TELEMETRY.md) for exactly what is sent. Opt out per run with the switches above, or for every tool by setting the environment variable `PICKERINGCLOUD_NOTELEMETRY=1` or `DO_NOT_TRACK=1`.
- **Secrets are masked in logs** on a best-effort basis (bearer tokens and password, secret, token or API key values).
- **Config files are excluded from source control** (see `.gitignore`) where they contain tenant identifiers, application IDs, or other environment-specific values - each tool creates a blank template on first run if one doesn't exist.
- **Destructive or environment-changing actions are opt-in**, not automatic on first run, where practical (e.g. OWA management requires `-Setup` to provision credentials; WSUS-ClientSync only reports without `-AutomaticallyRemediate`). Every tool supports `-WhatIf`.

### Upgrading from the `C:\Pickering-Cloud` layout

Earlier versions wrote logs and reports under `C:\Pickering-Cloud\...`. Existing files there are left alone, so update any monitoring or scripts that read them. Old parameters such as `-OutputRoot`, `-CustomLogPath` and `-LogRetentionDays` still work where a tool had them; each tool's README has the details.

## Getting started

1. Clone this repository.
2. Open the folder for the tool you need and follow its README.
3. Most tools will create a default config file on first run if one isn't already present - populate it (or run the tool's setup mode, where one exists) before relying on it for unattended use.

## Requirements

Requirements vary per script and are documented in each script's own README. As a general baseline, all scripts in this repository:

- Target Windows PowerShell 5.1 and/or PowerShell 7+, noted individually where a script is Windows-only versus cross-platform.

- Follow Microsoft's approved verb-noun naming convention.

- Include comment-based help (`Get-Help <ScriptName>.ps1 -Full`).

- Use `[CmdletBinding()]`, and `SupportsShouldProcess` on anything with a destructive or state-changing action, so `-WhatIf`/`-Confirm` are available where relevant.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Please note I am not guaranteeing timelines on resolving issues, including those which are script breaking.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

See [LICENSE](LICENSE). This applies repository-wide unless a specific script's folder contains its own LICENSE file stating otherwise.

## Author

Bradley Pickering

## Buy Me A Coffee

[Buy me a coffee](https://pckr.ing/bmac)
