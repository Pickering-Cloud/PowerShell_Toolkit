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
| **FileSigning** | Signs one or more files with a code signing certificate - uses an existing valid certificate if available, requests one from Active Directory Certificate Services (ADCS) if configured, or falls back to a self-signed certificate. Supports interactive file selection or a direct path, JSON-based policy configuration, and RFC 3161 timestamping. | [FileSigning/README.md](FileSigning/README.md) |
| **OutlookWebAccessManagement** | Queries an Entra tenant for users licensed with Microsoft 365 F1 / Office 365 F1, plus mailboxes with no licence granting Exchange access, and blocks Outlook client access (web, mobile, Mac, new Outlook) for both groups. Automatically restores access if a licence changes. Runs unattended via a certificate-based service principal. | [OutlookWebAccessManagement/README.md](OutlookWebAccessManagement/README.md) |
| **WSUS-ClientSync** | Forces a Windows client to check in against its configured WSUS server, runs diagnostics (DNS, reachability, certificate trust, pending reboot, disk space, disabled services), and optionally auto-remediates common synchronisation and installation errors. Designed to run across many machines via PowerShell remoting. | [WSUS-ClientSync/README.md](WSUS/ClientSync/README.md) |
## General conventions across these tools

- **Logs and reports** are written under `C:\Pickering-Cloud\...`, in a tool-specific subfolder (e.g. `C:\Pickering-Cloud\Logs\OWAManagement\`), rather than a hidden or system location - the aim is that anyone picking up a tool can find what happened without digging.
- **Config files are excluded from source control** (see `.gitignore`) where they contain tenant identifiers, application IDs, or other environment-specific values - each tool creates a blank template on first run if one doesn't exist.
- **Destructive or environment-changing actions are opt-in**, not automatic on first run, where practical (e.g. OWA management requires `-Setup` to provision credentials; FileSigning supports `-WhatIf`; WSUS-ClientSync only reports without `-AutomaticallyRemediate`).

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