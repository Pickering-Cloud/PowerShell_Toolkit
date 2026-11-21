# EntraAppExpiryScanner

Scans every Entra ID app registration in a tenant and reports on secrets and certificates that are expired or about to expire, apps with no owner, and apps with no credentials. Microsoft does not provide a clean built-in view of this, and an expired client secret is a common cause of unexpected outages.

The tool is **read-only**. It never changes anything in your tenant.

## Who it is for

| Audience | How it helps |
|----------|--------------|
| Individuals / small tenants | Run interactively, open the HTML report, renew what is flagged |
| Small and medium enterprises | Run weekly as a Scheduled Task and alert on the event log entries |
| Large organisations | Unattended certificate-based runs, CSV output for ingestion into other tooling |

## Features

- Secrets and certificates both covered
- Severity bands: Expired, Critical, Warning, Notice (all configurable)
- Flags app registrations with no owner
- Lists app registrations with no credentials
- HTML report with summary tiles, plus a CSV export
- Interactive or app-only authentication (certificate or client secret)
- Uses Microsoft Graph REST only, so only `Microsoft.Graph.Authentication` is needed
- Logging to a single appended, size-rotated log file with configurable level, plus Application event log entries
- Automatic 30-day retention cleanup of old reports (only this tool's own reports are touched)
- Optional update check and anonymous usage telemetry, each with its own opt-out
- Findings are reported, not treated as failures, so a successful scan always exits cleanly

## Requirements

**Platform**
- Windows PowerShell 5.1 or later. The event log entries need 5.1, as `Write-EventLog` is not available in PowerShell 7 (file logging still works there).
- Outbound HTTPS to `login.microsoftonline.com` and `graph.microsoft.com`
- Outbound HTTPS to `pickering.cloud` for the optional update check and telemetry (both can be disabled, see below)
- Outbound HTTPS to the PowerShell Gallery on first run, if `Microsoft.Graph.Authentication` is not already installed

**Modules**
- `Microsoft.Graph.Authentication` 2.0.0 or later. It is installed to the current user scope if missing, unless `-NoModuleInstall` is used. No other Graph modules are needed.

**Microsoft Graph permission**
- `Application.Read.All`, read-only
  - Interactive: delegated permission. Admin consent is required for it, so a Global Administrator, Cloud Application Administrator or Application Administrator must consent once for the tenant. After that, any account that can read app registrations can run the scan.
  - Unattended: **application** permission on an app registration of your own, with admin consent granted

**Unattended authentication**
- Certificate (recommended): the certificate must be in the certificate store of the account running the task, and that account needs read access to its private key.
- Client secret: supplied as a PSCredential. Note that this secret will itself expire, so it needs its own renewal reminder.

**Local permissions**
- Write access to the log and report folders. Both are created if they do not exist.
- An elevated session on first run only, to register the event log source. Without it the scan still runs and logs to file.

## Usage

```powershell
# Interactive, default thresholds (Critical 7, Warning 30, Notice 60 days)
.\EntraAppExpiryScanner.ps1

# Unattended with a certificate
.\EntraAppExpiryScanner.ps1 -TenantId contoso.onmicrosoft.com -ClientId <app-id> -CertificateThumbprint <thumbprint>

# Unattended with a client secret
$cred = Get-Credential   # username = client ID, password = client secret
.\EntraAppExpiryScanner.ps1 -TenantId contoso.onmicrosoft.com -ClientSecretCredential $cred

# Custom bands, hide anything already expired
.\EntraAppExpiryScanner.ps1 -CriticalDays 14 -WarningDays 45 -NoticeDays 90 -HideExpired

# Include credentials that are not due to expire soon
.\EntraAppExpiryScanner.ps1 -IncludeHealthy

# Preview retention cleanup without deleting anything
.\EntraAppExpiryScanner.ps1 -WhatIf
```

Certificate authentication is preferred over a client secret for unattended runs, as it avoids the scanner needing a secret that itself expires.

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-TenantId` | | Tenant ID or domain. Required for app-only, optional for interactive |
| `-ClientId` | | Client ID for certificate authentication |
| `-CertificateThumbprint` | | Selects certificate-based app-only authentication |
| `-ClientSecretCredential` | | PSCredential (client ID and secret). Selects secret-based app-only authentication |
| `-CriticalDays` | 7 | Expiring within this many days is Critical |
| `-WarningDays` | 30 | Expiring within this many days is Warning |
| `-NoticeDays` | 60 | Expiring within this many days is Notice |
| `-HideExpired` | off | Exclude already-expired credentials from the report |
| `-IncludeHealthy` | off | Include credentials outside the notice window |
| `-NoModuleInstall` | off | Do not install the Graph module automatically |
| `-LogPath` | `C:\ProgramData\PickeringCloud\EntraAppExpiryScanner\Logs\EntraAppExpiryScanner.log` | Full path of the log file |
| `-ReportPath` | `C:\ProgramData\PickeringCloud\EntraAppExpiryScanner\Reports\` | Folder for HTML and CSV reports |
| `-LoggingLevel` | Info (Debug with `-Debug`, Verbose with `-Verbose`) | Debug (1), Verbose (2), Info (3), Warn (4), Error (5), Critical (6), None (7 or 0). Name or number. An unrecognised value falls back to Info with a warning |
| `-RetentionDays` | 30 | Remove this tool's reports older than this. 0 disables cleanup. The log file is not affected |
| `-DisableUpdateCheck` | off | Do not check for a newer version |
| `-DisableTelemetry` | off | Do not send anonymous usage telemetry. The update check still runs unless `-DisableUpdateCheck` is also used |

Thresholds must satisfy `CriticalDays < WarningDays < NoticeDays`.

## Output

```
C:\ProgramData\PickeringCloud\EntraAppExpiryScanner\Logs\EntraAppExpiryScanner.log
C:\ProgramData\PickeringCloud\EntraAppExpiryScanner\Reports\EntraAppExpiryScanner_<timestamp>.html
C:\ProgramData\PickeringCloud\EntraAppExpiryScanner\Reports\EntraAppExpiryScanner_<timestamp>.csv
```

The CSV contains one row per finding. The `FindingType` column is `Credential`, `NoOwner` or `NoCredentials`.

Versions before 1.1.0 wrote to `C:\Pickering-Cloud\Logs\Entra\` and `C:\Pickering-Cloud\Reports\Entra\EntraAppExpiryScanner\`. Files already there are left alone. Pass `-LogPath` and `-ReportPath` to keep using those locations.

## Logging

Logging uses the toolkit standard: one appended log file plus a small set of Windows Application event log entries. The log file is created read-only on first run and appended to on every run. At 10 MB it is rotated, keeping five older copies. The script never prompts for a logging level, so it is safe to run unattended. Use `-LoggingLevel` to change it, or `-Debug` for Debug level. Secrets in log messages are masked on a best-effort basis, and the log is written during `-WhatIf` runs too.

The event log source `EntraAppExpiryScanner` is registered on first run, which needs an elevated session. If registration fails, the scan carries on and file logging is unaffected.

Finding expiring or expired credentials is the purpose of the tool, so findings are never logged as errors. Only a scan that fails to complete is an Error event.

| Event ID | Type | Meaning |
|----------|------|---------|
| 3000 | Information | Scan started |
| 3001 | Information | Completed, nothing at Warning severity or above |
| 3002 | Warning | Completed, at least one credential at Warning severity |
| 3003 | Warning | Completed, at least one Critical or Expired credential |
| 3010 | Error | The scan could not be completed |

To alert on findings, key off event IDs 3002 and 3003 in your monitoring tool.

## Update check and telemetry

After the scan finishes, the script does two optional things. Neither can affect the scan or its exit code, and any failure is ignored.

**Update check.** The script reads a small static file (`https://pickering.cloud/tools/versions.json`) and tells you if a newer version is available. It sends no data. In an interactive session it offers to open the release page, and in an unattended run it only writes a line to the log. It never downloads or installs anything. Disable it with `-DisableUpdateCheck`.

**Anonymous usage telemetry.** So the author can see roughly how many installs exist and which platforms to support, the script sends: tool name, tool version, OS name and build, PowerShell version and edition, timezone ID, and whether the run was interactive or unattended. The server adds the country from the request and a hash of the IP address that changes daily and cannot be linked across days. The raw IP address and User-Agent are never stored. No tenant, user, host or app registration data is ever sent. Disable it with `-DisableTelemetry`, or for every tool at once by setting the environment variable `PICKERINGCLOUD_NOTELEMETRY=1` or `DO_NOT_TRACK=1`.

App-only (certificate or client secret) runs are always treated as unattended and never prompt.

The two are independent. You can keep update checks and turn telemetry off. Run with `-Debug` to see the exact telemetry payload in the log. See `TELEMETRY.md` in the repository root for the full policy.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | The scan completed, whatever it found |
| 1 | The scan could not be completed (module, authentication or Graph failure) |

## Notes and limitations

- Only application objects are scanned. SAML signing certificates on enterprise applications (service principals) are not covered in this version.
- Owner checks use Graph `$batch`. If a lookup fails for an app, its owner state is shown as Unknown and it is not reported as ownerless.
- Expiry is calculated in whole days against the current UTC time.
- With `-HideExpired`, the summary tiles in the HTML report also exclude expired credentials.

## Licence and contributions

See the repository root for the licence, `CONTRIBUTING.md` and `SECURITY.md`.