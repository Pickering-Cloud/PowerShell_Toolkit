\# Changelog



All notable changes to this project are documented in this file.



The format is based on \[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to \[Semantic Versioning](https://semver.org/spec/v2.0.0.html).



\## \[Unreleased]



\## \[1.0.0] - 2026-08-18



\### Added



\- Interactive service principal setup (`-Setup`) creating an Entra app registration, self-signed authentication certificate, and required Graph/Exchange Online permissions, including the Exchange Administrator directory role.

\- Human-readable `config.psd1`, auto-created with blank defaults on first run and updated automatically after setup.

\- Tenant querying for users licensed with Microsoft 365 F1 or Office 365 F1 (`SPE\_F1` / `DESKLESSPACK`).

\- Tenant querying for mailboxes with no licence that grants Exchange access ("orphaned" mailboxes).

\- Blocking and unblocking of all five OWA-family client access settings per user: Outlook on the web, Outlook on the web for devices, Outlook Mobile, Outlook for Mac, and the new Outlook for Windows.

\- Persistent state file (`BlockedUsers.psd1`) tracking currently blocked users, enabling automatic unblock when a user no longer meets either blocking condition.

\- Dated CSV audit report of every block/unblock action, separate from the persistent state file.

\- Dated log file with INFO/WARN/ERROR/CRITICAL levels; CRITICAL halts the script after logging.

\- `Write-Progress` bars for the block and unblock passes during a run.

\- Full comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.OUTPUTS`, `.NOTES`) on every function and the main script.



\### Fixed



\- Interactive sign-in during setup now pins to the known tenant ID (if already configured) rather than relying on the signed-in account's default tenant, preventing the app registration from being created in the wrong tenant.

\- CRITICAL log entries now always halt the script, even if the log directory itself can't be created.

\- `Get-EXOMailbox` now explicitly requests `UserPrincipalName`, since it isn't guaranteed to be present in the cmdlet's default reduced property set - omitting it previously caused every mailbox to silently fail matching against the user list.

\- Single quotes in a blocked user's display name (e.g. `O'Brien`) are now escaped when writing the state file, preventing corruption of the generated `.psd1`.

\- Empty result sets from the F1 and orphaned-mailbox queries are now guaranteed to be genuine empty arrays rather than `$null`, preventing a crash in the block/unblock reconciliation step on any run where one of those lists is empty.

\- `$mailboxGrantingSkuParts` no longer includes `SPE\_F1` or `DESKLESSPACK` (previously matched via an overly broad `SPE\_` wildcard) - F1 licences do not grant a mailbox, so F1-only users are now correctly identified as orphaned rather than treated as adequately licensed.

