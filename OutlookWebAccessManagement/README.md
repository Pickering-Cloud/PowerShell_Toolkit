\# OWA Management for F1-Licensed Users



A PowerShell script that queries an Entra tenant for users holding an F1 licence (Microsoft 365 F1 or Office 365 F1), plus mailboxes with no licence that legitimately grants Exchange access, and blocks their Outlook client access accordingly. Tracks currently blocked users so access can be restored automatically once a licence changes.



\## What it does



\- Connects to Microsoft Graph and Exchange Online using a certificate-based service principal (no interactive sign-in required for normal runs).

\- Identifies users licensed with F1 (`SPE\_F1` / `DESKLESSPACK`) - these licences do not grant a mailbox, so any Outlook client access on an F1 mailbox needs to be blocked to stay licence-compliant.

\- Identifies mailboxes belonging to users with no licence that grants a mailbox at all (an "orphaned" mailbox - typically left over after a licence change).

\- Blocks all five OWA-family client access settings for identified users: Outlook on the web, Outlook on the web for devices, Outlook Mobile, Outlook for Mac, and the new Outlook for Windows.

\- Automatically restores access for anyone previously blocked who no longer meets either condition (e.g. their licence was upgraded).

\- Maintains a persistent state file of currently blocked users, a dated CSV audit report of every block/unblock action, and a dated log file of the full run.



\## Prerequisites



\- PowerShell 5.1 or PowerShell 7+

\- PowerShell modules: `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Applications`, `ExchangeOnlineManagement` (installed automatically on first run if missing)

\- For first-time setup only: an Entra account with \*\*Application Administrator\*\* (or \*\*Global Administrator\*\*) and \*\*Privileged Role Administrator\*\* rights

\- For unattended runs: the service principal created during setup needs the \*\*Exchange Administrator\*\* Entra directory role, and admin consent granted on its Graph application permissions



\## First-time setup



1\. Clone this repository.

2\. (Optional) If you already know your tenant ID, add it to `config.psd1` before running setup - this pins the interactive sign-in to the correct tenant if you have access to more than one.

3\. Run:

&nbsp;  ```powershell

&nbsp;  .\\OWA\_Management.ps1 -Setup

&nbsp;  ```

4\. Sign in interactively when prompted, using an account with the rights listed above.

5\. In the Entra portal, confirm \*\*admin consent\*\* has been granted for the application's Graph permissions (`User.Read.All`, `Organization.Read.All`) - this step is not automated.

6\. Certificate trust and the Exchange Administrator role assignment can take a few minutes to propagate. If the first run fails to connect to Exchange Online immediately after setup, wait a few minutes and try again.

7\. From this point on, run the script normally (see below) - `-Setup` doesn't need to be passed again unless the service principal is removed or the config is cleared.



\## Usage



```powershell

\# Normal run - queries the tenant and blocks/unblocks as needed

.\\OWA\_Management.ps1



\# First-time or re-provisioning run

.\\OWA\_Management.ps1 -Setup

```



Intended to be run on a schedule (Task Scheduler, Azure Automation, etc.) once set up.



\## Configuration



`config.psd1`, alongside the script (\*\*not committed to source control\*\* - see `.gitignore`):



```powershell

@{

&nbsp;   TenantId            = ""

&nbsp;   ClientId            = ""

&nbsp;   ClientThumbprint    = ""

}

```



Created automatically with blank values if missing. Populated automatically by `-Setup`.



\## Output locations



| What | Where |

|---|---|

| Log (per run day) | `C:\\Pickering-Cloud\\Logs\\OWAManagement\\yyyyMMdd.log` |

| CSV audit report (per run day) | `C:\\Pickering-Cloud\\Reports\\OWAManagement\\yyyyMMdd.csv` |

| Current block state | `C:\\Pickering-Cloud\\Reports\\OWAManagement\\BlockedUsers.psd1` |



\## How target users are identified



\- \*\*F1 licence holders\*\* - any user with `SPE\_F1` (Microsoft 365 F1) or `DESKLESSPACK` (Office 365 F1) in their assigned licences.

\- \*\*Orphaned mailboxes\*\* - any user with a mailbox but no licence matching the `$mailboxGrantingSkuParts` list in the script. This list deliberately excludes F1 SKUs, since F1 doesn't grant a mailbox in the first place.



Verify `$mailboxGrantingSkuParts` against your own tenant's SKUs (`Get-MgSubscribedSku | Select SkuPartNumber`) before relying on this in production - the shipped list covers common Business/Enterprise/Education plans but not every possible SKU.



\## Service principal permissions



| Permission | Type | Purpose |

|---|---|---|

| `User.Read.All` | Graph, Application | Read users and their assigned licences |

| `Organization.Read.All` | Graph, Application | Read subscribed SKUs and tenant domain |

| `Exchange.ManageAsApp` | Exchange Online, Application | Authenticate to Exchange Online as an app |

| Exchange Administrator | Entra directory role | Actually authorised to run `Set-CASMailbox` |



\## Known limitations



\- `OneWinNativeOutlookEnabled` requires a reasonably recent `ExchangeOnlineManagement` module version and may not exist in older installs - remove it from `$owaClientParameters` if you hit a "parameter not found" error.

\- `Write-Progress` output only appears in an interactive console session; it's silently discarded when run as an unattended scheduled task.

\- Module installation uses the default (`AllUsers`) scope, which typically requires an elevated session.



\## Author



Bradley Pickering

