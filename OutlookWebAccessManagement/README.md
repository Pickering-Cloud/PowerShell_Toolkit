# OWA Management for F1-Licensed Users

A PowerShell script that queries an Entra tenant for users holding an F1 licence (Microsoft 365 F1 or Office 365 F1), plus mailboxes with no licence that legitimately grants Exchange access, and blocks their Outlook client access accordingly. Tracks currently blocked users so access can be restored automatically once a licence changes.

## What it does

- Connects to Microsoft Graph and Exchange Online using a certificate-based service principal (no interactive sign-in required for normal runs).
- Identifies users licensed with F1 (`SPE_F1` / `DESKLESSPACK`) - these licences do not grant a mailbox, so any Outlook client access on an F1 mailbox needs to be blocked to stay licence-compliant.
- Identifies mailboxes belonging to users with no licence that grants a mailbox at all (an "orphaned" mailbox - typically left over after a licence change).
- Blocks all five OWA-family client access settings for identified users: Outlook on the web, Outlook on the web for devices, Outlook Mobile, Outlook for Mac, and the new Outlook for Windows.
- Automatically restores access for anyone previously blocked who no longer meets either condition (e.g. their licence was upgraded).
- Maintains a persistent state file of currently blocked users, a daily CSV audit report of every block/unblock action, and an appended log file of every run.

## Prerequisites

- PowerShell 5.1 or PowerShell 7+
- PowerShell modules: `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Applications`, `ExchangeOnlineManagement` (installed automatically on first run if missing)
- For first-time setup only: an Entra account with **Application Administrator** (or **Global Administrator**) and **Privileged Role Administrator** rights
- For unattended runs: the service principal created during setup needs the **Exchange Administrator** Entra directory role, and admin consent granted on its Graph application permissions

## First-time setup

1. Clone this repository.
2. (Optional) If you already know your tenant ID, add it to `config.psd1` before running setup - this pins the interactive sign-in to the correct tenant if you have access to more than one.
3. Run:
   ```powershell
   .\OWA_Management.ps1 -Setup
   ```
4. Sign in interactively when prompted, using an account with the rights listed above.
5. In the Entra portal, confirm **admin consent** has been granted for the application's Graph permissions (`User.Read.All`, `Organization.Read.All`) - this step is not automated.
6. Certificate trust and the Exchange Administrator role assignment can take a few minutes to propagate. If the first run fails to connect to Exchange Online immediately after setup, wait a few minutes and try again.
7. From this point on, run the script normally (see below) - `-Setup` doesn't need to be passed again unless the service principal is removed or the config is cleared.

## Usage

```powershell
# Normal run - queries the tenant and blocks/unblocks as needed
.\OWA_Management.ps1

# First-time or re-provisioning run
.\OWA_Management.ps1 -Setup

# Show who would be blocked or unblocked, without changing anything
.\OWA_Management.ps1 -WhatIf
```

Intended to be run on a schedule (Task Scheduler, Azure Automation, etc.) once set up. Run it from the script's folder, or set the task's "Start in" folder to it, since `config.psd1` is read from the current directory.

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Setup` | off | Runs interactive service principal creation if one is not already configured, then continues into a normal run. |
| `-LogPath` | `C:\ProgramData\PickeringCloud\OutlookWebAccessManagement\Logs\OutlookWebAccessManagement.log` | Log file location. |
| `-LoggingLevel` | `Info` | `Debug`, `Verbose`, `Info`, `Warn`, `Error`, `Critical` or `None` (or 1 to 7, with 0 also meaning `None`). `-Debug` and `-Verbose` raise it when this is not set. |
| `-ReportPath` | `C:\ProgramData\PickeringCloud\OutlookWebAccessManagement\Reports` | Folder for the daily audit CSV and the state file. |
| `-RetentionDays` | `0` | Audit CSVs older than this are removed. Defaults to `0` (keep everything), unlike the rest of the toolkit, because the CSVs are the audit trail. The state file is never removed. |
| `-DisableUpdateCheck` | off | Skips the check for a newer version. |
| `-DisableTelemetry` | off | Stops anonymous usage telemetry being sent. |

`-WhatIf` and `-Confirm` are supported. With `-WhatIf`, no mailbox is changed, the audit CSV and state file are not written, and no telemetry is sent. The log records what would have happened.

## Configuration

`config.psd1`, alongside the script (**not committed to source control** - see `.gitignore`):

```powershell
@{
    TenantId            = ""
    ClientId            = ""
    ClientThumbprint    = ""
}
```

Created automatically with blank values if missing. Populated automatically by `-Setup`.

## Output locations

| What | Where (defaults) |
|---|---|
| Log (appended every run, rotated at 10 MB) | `C:\ProgramData\PickeringCloud\OutlookWebAccessManagement\Logs\OutlookWebAccessManagement.log` |
| CSV audit report (one per run day) | `C:\ProgramData\PickeringCloud\OutlookWebAccessManagement\Reports\OutlookWebAccessManagement_yyyyMMdd.csv` |
| Current block state | `C:\ProgramData\PickeringCloud\OutlookWebAccessManagement\Reports\BlockedUsers.psd1` |

The state file always sits in the same folder as the audit CSVs (`-ReportPath`).

### Upgrading from 1.1.0 or earlier

Earlier versions wrote to `C:\Pickering-Cloud\Logs\OWAManagement\` and `C:\Pickering-Cloud\Reports\OWAManagement\`. On the first run after upgrading, if there is no state file in `-ReportPath` yet, the existing `C:\Pickering-Cloud\Reports\OWAManagement\BlockedUsers.psd1` is copied there, so users blocked by the old version can still be unblocked later. The old files are left in place.

## Update check and telemetry

After each run, the script checks `https://pickering.cloud/tools/versions.json` for a newer version (nothing is sent, and nothing is downloaded or installed) and sends anonymous usage telemetry: tool name and version, OS and build, PowerShell version and edition, timezone ID, and whether the run was interactive or unattended. No tenant, user, mailbox or licence details are ever sent. Neither can affect the result of the run, and an unattended run never prompts.

Disable them with `-DisableUpdateCheck` and `-DisableTelemetry`, or turn telemetry off for every tool by setting `PICKERINGCLOUD_NOTELEMETRY=1` or `DO_NOT_TRACK=1`. See `TELEMETRY.md` in the repository root for the full policy.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The run completed. This includes the first run, which creates a blank `config.psd1` and stops. |
| 1 | The run failed: service principal not configured (and `-Setup` not used), a connection failure, or a Graph or Exchange Online query that failed. |

## Event log

Failures are logged to file. The script also registers an Application event log source, `OutlookWebAccessManagement`, which needs an elevated session once. It does not currently write any events of its own.

## How target users are identified

- **F1 licence holders** - any user with `SPE_F1` (Microsoft 365 F1) or `DESKLESSPACK` (Office 365 F1) in their assigned licences.
- **Orphaned mailboxes** - any user with a mailbox but no licence matching the `$mailboxGrantingSkuParts` list in the script. This list deliberately excludes F1 SKUs, since F1 doesn't grant a mailbox in the first place.

Verify `$mailboxGrantingSkuParts` against your own tenant's SKUs (`Get-MgSubscribedSku | Select SkuPartNumber`) before relying on this in production - the shipped list covers common Business/Enterprise/Education plans but not every possible SKU.

## Service principal permissions

| Permission | Type | Purpose |
|---|---|---|
| `User.Read.All` | Graph, Application | Read users and their assigned licences |
| `Organization.Read.All` | Graph, Application | Read subscribed SKUs and tenant domain |
| `Exchange.ManageAsApp` | Exchange Online, Application | Authenticate to Exchange Online as an app |
| Exchange Administrator | Entra directory role | Actually authorised to run `Set-CASMailbox` |

## Known limitations

- `OneWinNativeOutlookEnabled` requires a reasonably recent `ExchangeOnlineManagement` module version and may not exist in older installs - remove it from `$owaClientParameters` if you hit a "parameter not found" error.
- `Write-Progress` output only appears in an interactive console session; it's silently discarded when run as an unattended scheduled task.
- Missing modules are installed to the current user's scope, so a Scheduled Task running as a different account needs them installed for that account (or for all users).

## Author

Bradley Pickering
