# Manage-OWA

Blocks Outlook client access (Outlook on the web, mobile and desktop clients) for Microsoft 365 users whose licensing does not entitle them to an Exchange Online mailbox, and restores access automatically when their licensing changes.

Designed to run unattended, for example as a nightly scheduled task, using a certificate-authenticated service principal.

## Why this exists

Microsoft 365 F1 and Office 365 F1 licences do not include rights to an Exchange Online mailbox. A mailbox can still exist for these users, and nothing stops them signing in to Outlook on the web. This script finds those users, and any other mailbox holder with no licence that grants Exchange, and switches off their Outlook client access so that the tenant stays within its licence terms.

## What it does

1. Connects to Microsoft Graph and Exchange Online using the configured service principal and certificate.
2. Reads the tenant's subscribed SKUs, users and mailboxes.
3. Builds a list of users to block:
   - **F1 Licence**: users assigned `SPE_F1` or `DESKLESSPACK`.
   - **No qualifying mailbox licence**: mailbox holders whose assigned licences do not include any SKU in the mailbox-granting list (see [Configuration](#configuration)).
4. Compares that list with the saved state from the previous run:
   - Users newly in scope are blocked.
   - Users who were blocked but are no longer in scope (for example after a licence upgrade) are unblocked.
   - A failed unblock is kept in the state and retried on the next run.
5. Appends every block and unblock to a dated CSV report and saves the new state file.
6. Disconnects from both services.

Blocking sets the following `Set-CASMailbox` parameters to `$false`: `OWAEnabled`, `OWAforDevicesEnabled`, `OutlookMobileEnabled`, `MacOutlookEnabled` and `OneWinNativeOutlookEnabled`.

## Requirements

| Requirement | Detail |
| --- | --- |
| PowerShell | Windows PowerShell 5.1 or PowerShell 7 |
| Modules | `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Applications`, `ExchangeOnlineManagement` |
| Setup rights (one-off) | Application Administrator (or Global Administrator) and Privileged Role Administrator in Entra |
| Service principal | Graph application permissions `User.Read.All` and `Organization.Read.All`, Exchange Online application permission `Exchange.ManageAsApp`, and the Exchange Administrator directory role |
| Certificate | Self-signed certificate in the certificate store of the account running the script (created by `-Setup`) |

Missing modules are installed for the current user automatically. The account running the script therefore needs access to the PowerShell Gallery on first run, or the modules must be installed beforehand.

## Quick start

1. Run the script once. It creates a blank `config.psd1` next to where you ran it and exits.

   ```powershell
   .\Manage-OWA.ps1
   ```

2. Run the interactive setup as an administrator holding the rights above. This creates the app registration, certificate, permissions and role assignment, and writes the values into `config.psd1`.

   ```powershell
   .\Manage-OWA.ps1 -Setup
   ```

3. In the Entra admin centre, open the new app registration (`OWA-Manage-F1-Automation` by default) and grant admin consent for its application permissions.
4. Wait a few minutes. Certificate trust and role assignment take time to propagate, and the first Exchange Online connection can fail until they do.
5. Run the script again without `-Setup` to confirm a normal run completes.
6. Schedule it (see [Scheduling](#scheduling)).

## Parameters

| Parameter | Description |
| --- | --- |
| `-Setup` | Runs the interactive service principal creation if none is configured. Not needed on normal runs. |
| `-DisableUpdateCheck` | Skips the check for a newer version. |
| `-DisableTelemetry` | Stops anonymous usage telemetry being sent. |

## Configuration

`config.psd1` is read from the current working directory and holds three values:

```powershell
@{
    TenantId         = ""
    ClientId         = ""
    ClientThumbprint = ""
}
```

`-Setup` fills these in for you. If you configure a service principal by hand, enter your own values.

The mailbox-granting SKU list is held in `$mailboxGrantingSkuParts` near the top of the script. A SKU is matched if its part number contains any entry in the list. Review it against the SKUs your tenant actually holds before the first live run, because a user holding only a SKU that is not on the list is treated as having no mailbox licence and is blocked.

## Output

| Item | Default location |
| --- | --- |
| Log file | `C:\Pickering-Cloud\Logs\OWAManagement\yyyyMMdd.log` |
| Report | `C:\Pickering-Cloud\Reports\OWAManagement\yyyyMMdd.csv` |
| State file | `C:\Pickering-Cloud\Reports\OWAManagement\BlockedUsers.psd1` |

The report records the user principal name, display name, action (`Blocked` or `Unblocked`) and reason. The state file lists currently blocked users with the date they were blocked and why. Do not delete it: it is how the script knows whom to unblock later.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Run completed, or a default `config.psd1` was created |
| 1 | A critical error stopped the run (for example missing configuration or a failed connection) |

## Scheduling

Run the script from a scheduled task under the account that holds the certificate, with the working directory set to the folder containing `config.psd1`.

```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\Manage-OWA\Manage-OWA.ps1"' `
    -WorkingDirectory 'C:\Scripts\Manage-OWA'
$trigger = New-ScheduledTaskTrigger -Daily -At 02:00
Register-ScheduledTask -TaskName 'Manage-OWA' -Action $action -Trigger $trigger -RunLevel Highest
```

Set the task to run as the account whose certificate store holds the service principal certificate.

## Update check and telemetry

After each run the script can check for a newer version and send anonymous usage data. Both are optional and independent of each other, and neither can change the outcome of the run.

**Update check.** A plain GET request to `https://pickering.cloud/tools/versions.json` with a generic user agent. Nothing is sent. If a newer version exists the script tells you and writes the notice to the log. In an interactive session it also offers to open the release page (GitHub links only). In an unattended session it never prompts. It never downloads or installs anything.

**Telemetry.** A single anonymous POST to `https://pickering.cloud/api/telemetry` containing the tool name and version, OS name and build, PowerShell version and edition, timezone ID and whether the run was interactive or unattended. The server also records the country (taken from the request) and a daily salted hash of the IP address, so repeat use can be counted without storing the address. No tenant ID, user, mailbox or licence information is ever sent. Run the script with `-Verbose` to see the exact payload. The full disclosure is in `TELEMETRY.md` in the repository root.

To opt out:

| Method | Effect |
| --- | --- |
| `-DisableUpdateCheck` | No version check |
| `-DisableTelemetry` | No telemetry |
| `PICKERINGCLOUD_NOTELEMETRY=1` (or `true`) | No telemetry in any tool in this toolkit, for every user of the machine if set system-wide |

## Safety notes

- The script changes mailbox settings for real. There is no `-WhatIf` mode in this version, so test against a small tenant or review the SKU list and your F1 population first.
- Blocking affects Outlook on the web, mobile and desktop clients. It does not remove the mailbox, and mail continues to be delivered.
- The service principal holds the Exchange Administrator role. Protect the certificate's private key and restrict who can read the scheduled task account's certificate store.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Exchange Online connection fails straight after `-Setup` | Role and certificate propagation delay. Wait several minutes and run again. |
| "Service principal not configured" | `config.psd1` is empty, or the script was started from a different working directory. |
| Everyone is reported as having no qualifying licence | The tenant uses a SKU that is not in `$mailboxGrantingSkuParts`. |
| "No F1 SKU found in tenant" | No `SPE_F1` or `DESKLESSPACK` SKU is subscribed. This is a warning, not a failure. |
| Graph calls return 403 | Admin consent has not been granted to the application permissions. |

## Licence and support

Part of the [Pickering-Cloud PowerShell Toolkit](https://github.com/Pickering-Cloud/PowerShell_Toolkit). See the repository for licence terms, and the [CHANGELOG](CHANGELOG.md) for version history.