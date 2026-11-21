# ADAccountAudit

Read-only Active Directory reporting tool for single-crewed or small-team sysadmins. Finds stale accounts, disabled-but-privileged accounts, accounts with a password about to expire, and empty security groups, and writes the results to an HTML report and CSV export. Makes no changes to Active Directory.

## Overview

`ADAccountAudit.ps1` checks four things on every run:

1. **Stale accounts** — enabled accounts with no logon activity in `-StaleDays` or more (default 90), based on `LastLogonTimestamp`.
2. **Disabled accounts in privileged groups** — accounts disabled but still holding membership (including nested/recursive membership) of one or more groups named in `-PrivilegedGroups`.
3. **Expiring passwords** — enabled accounts whose password will expire within `-PasswordExpiryWarningDays` (default 14), using the computed `msDS-UserPasswordExpiryTimeComputed` attribute, so fine-grained password policies are respected. Accounts with `PasswordNeverExpires` set are excluded.
4. **Empty groups** — security groups with zero members. Distribution groups are excluded by default, since they carry no access implications; pass `-IncludeDistributionGroups` to include them.

It's designed to run unattended via Scheduled Task: no prompts, exit code 0 on success, exit code 1 on any fatal error. Reports older than `-RetentionDays` are cleaned up automatically at the end of each run, and the log file rotates by size.

## Usage

```powershell
# Run with all defaults
.\ADAccountAudit.ps1

# Custom stale threshold, custom privileged groups, include distribution groups
.\ADAccountAudit.ps1 -StaleDays 60 -PrivilegedGroups @("Domain Admins","Backup Operators") -IncludeDistributionGroups

# Scope to a specific OU
.\ADAccountAudit.ps1 -SearchBase "OU=Users,OU=London,DC=contoso,DC=com"

# Write reports to a share and keep them for 90 days
.\ADAccountAudit.ps1 -ReportPath \\fileserver\Reports\ADAudit -RetentionDays 90
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-StaleDays` | int | `90` | Days since last logon after which an enabled account is flagged as stale. |
| `-PasswordExpiryWarningDays` | int | `14` | Days before password expiry to flag an account. |
| `-PrivilegedGroups` | string[] | `Domain Admins, Enterprise Admins, Schema Admins, Administrators` | Groups checked (recursively) for disabled-but-still-privileged membership. |
| `-SearchBase` | string | domain root | Distinguished name to scope all searches to a specific OU. |
| `-IncludeDistributionGroups` | switch | off | Also reports empty distribution groups, not just security groups. |
| `-LogPath` | string | `C:\ProgramData\PickeringCloud\ADAccountAudit\Logs\ADAccountAudit.log` | Log file location. |
| `-LoggingLevel` | string | `Info` | `Debug`, `Verbose`, `Info`, `Warn`, `Error`, `Critical` or `None` (or 1 to 7, with 0 also meaning `None`). `-Debug` and `-Verbose` raise it when this is not set. |
| `-ReportPath` | string | `C:\ProgramData\PickeringCloud\ADAccountAudit\Reports` | Folder for the HTML report and CSV exports. |
| `-RetentionDays` | int | `30` | Reports older than this are removed. `0` disables cleanup. Only this tool's own reports are removed. |
| `-DisableUpdateCheck` | switch | off | Skips the check for a newer version. |
| `-DisableTelemetry` | switch | off | Stops anonymous usage telemetry being sent. |
| `-OutputRoot` | string | none | **Deprecated.** When supplied, uses the pre-1.1.0 layout: log at `<OutputRoot>\Logs\ADAccountAudit.log`, reports in `<OutputRoot>\Reports`, unless `-LogPath` or `-ReportPath` is also given. |
| `-LogRetentionDays` | int | | **Deprecated** alias of `-RetentionDays`. |

`-WhatIf` is supported. The audit itself never changes anything, but `-WhatIf` also stops the script installing RSAT if the ActiveDirectory module is missing (the run then stops, since the audit needs the module).

## Output

- **HTML report** — `<ReportPath>\ADAccountAudit_<timestamp>.html`. Colour-coded findings with a summary count at the top.
- **CSV exports** — one per finding category, alongside the HTML report: `..._StaleAccounts.csv`, `..._DisabledPrivileged.csv`, `..._ExpiringPasswords.csv`, `..._EmptyGroups.csv`.
- **Log file** — `<LogPath>`, a single file appended to on every run and rotated at 10 MB.

Versions before 1.1.0 wrote a log per run under `C:\Pickering-Cloud\ADAccountAudit\Logs` and reports under `C:\Pickering-Cloud\ADAccountAudit\Reports` by default. Files already there are left alone. Pass `-OutputRoot C:\Pickering-Cloud\ADAccountAudit` to keep using that location.

## Update check and telemetry

After each run, the script checks `https://pickering.cloud/tools/versions.json` for a newer version (nothing is sent, and nothing is downloaded or installed) and sends anonymous usage telemetry: tool name and version, OS and build, PowerShell version and edition, timezone ID, and whether the run was interactive or unattended. No domain, user, group or host details are ever sent. Neither can affect the result of the run.

Disable them with `-DisableUpdateCheck` and `-DisableTelemetry`, or turn telemetry off for every tool by setting `PICKERINGCLOUD_NOTELEMETRY=1` or `DO_NOT_TRACK=1`. See `TELEMETRY.md` in the repository root for the full policy.

## Requirements

- Windows PowerShell 5.1.
- ActiveDirectory PowerShell module (RSAT). The script attempts to install this automatically if missing — `Add-WindowsCapability` on Windows 10/11 client, `Install-WindowsFeature RSAT-AD-PowerShell` on Windows Server — which requires an elevated session. If automatic installation isn't possible, the script logs the exact manual command and exits.
- Read access to the domain. No elevated AD permissions are required beyond standard authenticated-user read access, since this script only reads, it never writes to AD.

## Known limitations

- `LastLogonTimestamp` replicates across domain controllers with up to 14 days of lag by design. Treat stale-account findings as approximate, not exact, particularly near the threshold boundary.
- Has not been run against a live domain by the author at the time of writing. Test with `-SearchBase` scoped to a small OU before running against the full domain, particularly the password expiry and empty-group logic, which are the two areas most likely to need adjustment for a given schema/environment.
- Does not remediate anything. This is a reporting tool only; any account or group changes are left to the administrator, or to a separate tool that consumes this one's CSV output.

## License

See [`LICENSE`](../LICENSE) at the repository root.