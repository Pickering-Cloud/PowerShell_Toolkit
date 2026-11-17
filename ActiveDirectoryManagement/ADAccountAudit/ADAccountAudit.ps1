<#
.SYNOPSIS
    Audits Active Directory for stale accounts, disabled-but-privileged accounts,
    accounts nearing password expiry, and empty security groups.

.DESCRIPTION
    Read-only reporting tool. Makes no changes to Active Directory.

    Produces four findings:
      1. Enabled accounts with no logon activity in more than -StaleDays days.
      2. Disabled accounts still holding membership (including nested/recursive)
         of one or more privileged groups.
      3. Enabled accounts whose password will expire within -PasswordExpiryWarningDays
         days (accounts with PasswordNeverExpires are excluded).
      4. Security groups with zero members. Distribution groups are excluded
         by default; pass -IncludeDistributionGroups to include them.

    Outputs a single HTML report (colour-coded, summary counts at the top) and
    a matching CSV export per run, plus a transcript-style log file. Old logs
    and reports beyond -LogRetentionDays are cleaned up automatically at the
    start of each run.

    Designed to run unattended via Scheduled Task: no prompts, exit code 0 on
    success, exit code 1 on any fatal error.

.PARAMETER StaleDays
    Number of days since last logon (via LastLogonTimestamp) after which an
    enabled account is flagged as stale. Default 90.
    Note: LastLogonTimestamp replicates across DCs with up to 14 days of lag
    by design, so treat this as "roughly this stale", not exact.

.PARAMETER PasswordExpiryWarningDays
    Number of days before password expiry to flag an account. Default 14.

.PARAMETER PrivilegedGroups
    Array of group names to check disabled-but-still-privileged membership
    against. Membership is checked recursively (nested groups included).
    Default: Domain Admins, Enterprise Admins, Schema Admins, Administrators.

.PARAMETER SearchBase
    Optional distinguished name to scope all searches to a specific OU.
    Defaults to the whole domain if not supplied.

.PARAMETER IncludeDistributionGroups
    Switch. Also reports empty distribution groups, not just security groups.

.PARAMETER OutputRoot
    Root folder for logs and reports. Default C:\Pickering-Cloud\ADAccountAudit.

.PARAMETER LogRetentionDays
    Number of days to retain log and report files before automatic cleanup.
    Default 30.

.EXAMPLE
    .\ADAccountAudit.ps1

    Runs with all defaults: 90-day stale threshold, 14-day password expiry
    warning, default privileged group list, whole-domain scope, security
    groups only, 30-day file retention.

.EXAMPLE
    .\ADAccountAudit.ps1 -StaleDays 60 -PrivilegedGroups @("Domain Admins","Backup Operators") -IncludeDistributionGroups

    Runs with a 60-day stale threshold, a custom privileged group list, and
    includes empty distribution groups in the report.

.OUTPUTS
    None to the pipeline. Writes an HTML report and CSV export to
    $OutputRoot\Reports, and a log file to $OutputRoot\Logs. Exits with code 0
    on success, 1 on fatal error.

.NOTES
    Author: Bradley Pickering
    Requires: ActiveDirectory PowerShell module (RSAT). The script will
    attempt to install this automatically if missing - see Install-RequiredModules.
    Read-only: performs no writes, disables, or membership changes against AD.
#>

param(
    [int]$StaleDays = 90,
    [int]$PasswordExpiryWarningDays = 14,
    [string[]]$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"),
    [string]$SearchBase,
    [switch]$IncludeDistributionGroups,
    [string]$OutputRoot = "C:\Pickering-Cloud\ADAccountAudit",
    [int]$LogRetentionDays = 30
)

##################################################
# Logging
##################################################

$Script:date = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:logPath = Join-Path $OutputRoot "Logs\ADAccountAudit_$($Script:date).log"
$Script:reportFolder = Join-Path $OutputRoot "Reports"
$Script:reportBaseName = "ADAccountAudit_$($Script:date)"

function Configure-LogPath {
    <#
    .SYNOPSIS
        Ensures the log directory exists.
    .DESCRIPTION
        Checks whether the parent directory of $logPath exists, creating it if
        necessary. Called internally by Write-Log before every write, so the
        log directory is created on demand rather than requiring manual setup.
    .OUTPUTS
        System.Boolean
    #>
    $logDir = Split-Path -Path $Script:logPath -Parent

    if (-not (Test-Path $logDir)) {
        Try {
            New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null
        }
        Catch {
            Write-Error "Failed creating log path: $logDir"
            return $false
        }
    }

    return $true
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped, levelled message to the log file and console.
    .DESCRIPTION
        Appends an entry to the log file at $logPath and echoes it to the
        console. CRITICAL-level messages exit the script with code 1 after
        being logged, regardless of whether the log file itself could be
        written, so a broken logging path can never silently swallow a fatal
        error.
    .PARAMETER Message
        The text to log.
    .PARAMETER Level
        Severity of the entry. One of INFO, WARN, ERROR, CRITICAL. Defaults to
        INFO. CRITICAL causes the script to exit after logging.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "CRITICAL")]
        [string]$Level = "INFO"
    )
    $prefix = "[$Level]"

    if (Configure-LogPath) {
        $time = Get-Date -Format "HH:mm:ss.fff"
        $entry = "$time | $prefix | $Message"
        Add-Content -Value $entry -Path $Script:logPath
        Write-Host $entry
    }
    else {
        Write-Host "$prefix | $Message (log file unavailable)" -ForegroundColor Red
    }

    if ($Level -eq "CRITICAL") {
        exit 1
    }
}

##################################################
# Retention cleanup
##################################################

function Remove-OldFiles {
    <#
    .SYNOPSIS
        Deletes files older than a given number of days from a folder.
    .DESCRIPTION
        Used at script start to clean up old logs and reports beyond the
        configured retention period. Non-fatal on individual failures - logs a
        WARN and continues, since a locked file shouldn't stop the audit run.
    .PARAMETER Path
        Folder to clean.
    .PARAMETER RetentionDays
        Files with a LastWriteTime older than this many days are removed.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [int]$RetentionDays
    )
    if (-not (Test-Path $Path)) { return }

    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    $oldFiles = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff }

    foreach ($file in $oldFiles) {
        Try {
            Remove-Item -Path $file.FullName -Force -ErrorAction Stop
            Write-Log -Message "Removed old file beyond ${RetentionDays}-day retention: $($file.FullName)" -Level INFO
        }
        Catch {
            Write-Log -Message "Failed to remove old file $($file.FullName): $($_.Exception.Message)" -Level WARN
        }
    }
}

##################################################
# Module bootstrap
##################################################

function Install-RequiredModules {
    <#
    .SYNOPSIS
        Ensures the ActiveDirectory module is available, installing it if not.
    .DESCRIPTION
        The ActiveDirectory module ships as part of RSAT, not the PowerShell
        Gallery, so it can't be pulled with Install-Module. This attempts the
        correct install path for the local OS (Add-WindowsCapability on
        Windows 10/11 client, Install-WindowsFeature on Windows Server), then
        imports the module. Requires an elevated session to succeed. Fails
        with a CRITICAL log entry and the manual install command if automatic
        installation isn't possible.
    #>
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Log -Message "ActiveDirectory module already available." -Level INFO
        Import-Module ActiveDirectory -ErrorAction Stop
        return
    }

    Write-Log -Message "ActiveDirectory module not found. Attempting automatic install via RSAT." -Level WARN

    Try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os.ProductType -eq 1) {
            # Windows client (10/11)
            Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop | Out-Null
        }
        else {
            # Windows Server
            Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop | Out-Null
        }
        Write-Log -Message "RSAT AD PowerShell tools installed successfully." -Level INFO
    }
    Catch {
        Write-Log -Message "Automatic install of the ActiveDirectory module failed: $($_.Exception.Message). Install RSAT manually - 'Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' on Windows 10/11, or 'Install-WindowsFeature RSAT-AD-PowerShell' on Windows Server - then re-run this script." -Level CRITICAL
    }

    Import-Module ActiveDirectory -ErrorAction Stop
}

##################################################
# Audit functions
##################################################

function Get-StaleAccounts {
    <#
    .SYNOPSIS
        Finds enabled accounts with no logon activity within the stale threshold.
    .DESCRIPTION
        Uses LastLogonTimestamp, converting the stored FileTime value to a
        DateTime. Accounts that have never logged on (null timestamp) are
        included, since "never logged on" is at least as notable as "stale".
    .OUTPUTS
        Array of PSCustomObject.
    #>
    Write-Log -Message "Checking for stale accounts (no logon in $StaleDays+ days)..." -Level INFO

    $adParams = @{
        Filter     = "Enabled -eq 'True'"
        Properties = @("LastLogonTimestamp", "whenCreated", "DisplayName")
    }
    if ($SearchBase) { $adParams["SearchBase"] = $SearchBase }

    $users = Get-ADUser @adParams
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    $results = @()

    foreach ($user in $users) {
        $lastLogon = $null
        if ($user.LastLogonTimestamp) {
            $lastLogon = [DateTime]::FromFileTime($user.LastLogonTimestamp)
        }

        if ($null -eq $lastLogon -or $lastLogon -lt $cutoff) {
            $results += [PSCustomObject]@{
                SamAccountName = $user.SamAccountName
                DisplayName    = $user.DisplayName
                LastLogon      = if ($lastLogon) { $lastLogon.ToString("yyyy-MM-dd") } else { "Never" }
                Created        = $user.whenCreated.ToString("yyyy-MM-dd")
                DistinguishedName = $user.DistinguishedName
            }
        }
    }

    Write-Log -Message "Found $($results.Count) stale account(s)." -Level INFO
    return $results
}

function Get-DisabledPrivilegedAccounts {
    <#
    .SYNOPSIS
        Finds disabled accounts still holding privileged group membership.
    .DESCRIPTION
        Checks each group named in $PrivilegedGroups recursively, so nested
        group membership is caught, not just direct membership. Missing
        groups are logged as a WARN and skipped rather than failing the run.
    .OUTPUTS
        Array of PSCustomObject.
    #>
    Write-Log -Message "Checking for disabled accounts in privileged groups..." -Level INFO

    $results = @()

    foreach ($groupName in $PrivilegedGroups) {
        Try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop |
                Where-Object { $_.objectClass -eq "user" }
        }
        Catch {
            Write-Log -Message "Could not enumerate group '$groupName': $($_.Exception.Message)" -Level WARN
            continue
        }

        foreach ($member in $members) {
            Try {
                $user = Get-ADUser -Identity $member.distinguishedName -Properties Enabled, DisplayName -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Could not resolve member $($member.distinguishedName): $($_.Exception.Message)" -Level WARN
                continue
            }

            if (-not $user.Enabled) {
                $results += [PSCustomObject]@{
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    PrivilegedGroup   = $groupName
                    DistinguishedName = $user.DistinguishedName
                }
            }
        }
    }

    Write-Log -Message "Found $($results.Count) disabled-but-privileged account(s)." -Level INFO
    return $results
}

function Get-ExpiringPasswords {
    <#
    .SYNOPSIS
        Finds enabled accounts whose password expires within the warning window.
    .DESCRIPTION
        Uses the computed msDS-UserPasswordExpiryTimeComputed attribute, which
        correctly accounts for fine-grained password policies. Accounts with
        PasswordNeverExpires set are excluded.
    .OUTPUTS
        Array of PSCustomObject.
    #>
    Write-Log -Message "Checking for passwords expiring within $PasswordExpiryWarningDays days..." -Level INFO

    $adParams = @{
        Filter     = "Enabled -eq 'True' -and PasswordNeverExpires -eq 'False'"
        Properties = @("DisplayName", "msDS-UserPasswordExpiryTimeComputed")
    }
    if ($SearchBase) { $adParams["SearchBase"] = $SearchBase }

    $users = Get-ADUser @adParams
    $warningCutoff = (Get-Date).AddDays($PasswordExpiryWarningDays)
    $results = @()

    foreach ($user in $users) {
        $expiryRaw = $user."msDS-UserPasswordExpiryTimeComputed"
        if (-not $expiryRaw -or $expiryRaw -eq 0 -or $expiryRaw -eq 9223372036854775807) {
            continue
        }

        $expiryDate = [DateTime]::FromFileTime($expiryRaw)

        if ($expiryDate -lt $warningCutoff) {
            $daysRemaining = [math]::Round(($expiryDate - (Get-Date)).TotalDays)
            $results += [PSCustomObject]@{
                SamAccountName    = $user.SamAccountName
                DisplayName       = $user.DisplayName
                ExpiryDate        = $expiryDate.ToString("yyyy-MM-dd")
                DaysRemaining     = $daysRemaining
                DistinguishedName = $user.DistinguishedName
            }
        }
    }

    Write-Log -Message "Found $($results.Count) account(s) with password expiring soon." -Level INFO
    return $results
}

function Get-EmptyGroups {
    <#
    .SYNOPSIS
        Finds security groups (and optionally distribution groups) with zero members.
    .DESCRIPTION
        Security groups are included by default since an empty security group
        can silently mean "nobody currently has this access" if referenced in
        an ACL, GPO, or application role. Distribution groups carry no access
        implications and are excluded by default to keep the report focused
        on actionable security findings; pass -IncludeDistributionGroups to
        include them anyway.
    .OUTPUTS
        Array of PSCustomObject.
    #>
    Write-Log -Message "Checking for empty groups..." -Level INFO

    $adParams = @{
        Filter     = "*"
        Properties = @("Members", "GroupCategory", "Description")
    }
    if ($SearchBase) { $adParams["SearchBase"] = $SearchBase }

    $groups = Get-ADGroup @adParams
    $results = @()

    foreach ($group in $groups) {
        if ($group.Members.Count -gt 0) { continue }
        if (-not $IncludeDistributionGroups -and $group.GroupCategory -eq "Distribution") { continue }

        $results += [PSCustomObject]@{
            GroupName         = $group.Name
            GroupCategory     = $group.GroupCategory
            Description       = $group.Description
            DistinguishedName = $group.DistinguishedName
        }
    }

    Write-Log -Message "Found $($results.Count) empty group(s)." -Level INFO
    return $results
}

##################################################
# Report generation
##################################################

function Export-AuditCsv {
    <#
    .SYNOPSIS
        Writes each finding set to its own CSV file for filtering in Excel.
    #>
    param(
        [Parameter(Mandatory)][array]$StaleAccounts,
        [Parameter(Mandatory)][array]$PrivilegedDisabled,
        [Parameter(Mandatory)][array]$ExpiringPasswords,
        [Parameter(Mandatory)][array]$EmptyGroups
    )

    $csvSets = @{
        "StaleAccounts"      = $StaleAccounts
        "DisabledPrivileged" = $PrivilegedDisabled
        "ExpiringPasswords"  = $ExpiringPasswords
        "EmptyGroups"        = $EmptyGroups
    }

    foreach ($name in $csvSets.Keys) {
        $path = Join-Path $Script:reportFolder "$($Script:reportBaseName)_$name.csv"
        if ($csvSets[$name].Count -gt 0) {
            $csvSets[$name] | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        }
        else {
            "No findings" | Out-File -FilePath $path -Encoding UTF8
        }
        Write-Log -Message "Wrote CSV: $path" -Level INFO
    }
}

function Build-HtmlSection {
    <#
    .SYNOPSIS
        Builds one colour-coded HTML table section for the report.
    #>
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][array]$Data,
        [Parameter(Mandatory)][string]$RowClass
    )

    if ($Data.Count -eq 0) {
        return "<h2>$Title</h2><p class='ok'>No findings.</p>"
    }

    $headers = $Data[0].PSObject.Properties.Name
    $headerRow = ($headers | ForEach-Object { "<th>$_</th>" }) -join ""

    $rows = foreach ($item in $Data) {
        $cells = ($headers | ForEach-Object { "<td>$($item.$_)</td>" }) -join ""
        "<tr class='$RowClass'>$cells</tr>"
    }

    return "<h2>$Title ($($Data.Count))</h2><table><tr>$headerRow</tr>$($rows -join '')</table>"
}

function Export-AuditHtml {
    <#
    .SYNOPSIS
        Builds and writes the full HTML report.
    #>
    param(
        [Parameter(Mandatory)][array]$StaleAccounts,
        [Parameter(Mandatory)][array]$PrivilegedDisabled,
        [Parameter(Mandatory)][array]$ExpiringPasswords,
        [Parameter(Mandatory)][array]$EmptyGroups
    )

    $style = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; color: #222; }
h1 { border-bottom: 2px solid #333; padding-bottom: 8px; }
h2 { margin-top: 30px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 10px; }
th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 13px; }
th { background-color: #333; color: #fff; }
tr.warn { background-color: #fff3cd; }
tr.risk { background-color: #f8d7da; }
p.ok { color: #2e7d32; font-weight: bold; }
.summary { background-color: #f5f5f5; border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; }
.summary span { display: inline-block; margin-right: 30px; font-weight: bold; }
.footnote { font-size: 12px; color: #666; margin-top: 40px; }
</style>
"@

    $summary = @"
<div class='summary'>
<span>Stale accounts: $($StaleAccounts.Count)</span>
<span>Disabled but privileged: $($PrivilegedDisabled.Count)</span>
<span>Expiring passwords: $($ExpiringPasswords.Count)</span>
<span>Empty groups: $($EmptyGroups.Count)</span>
</div>
"@

    $body = ""
    $body += Build-HtmlSection -Title "Stale Accounts (no logon $StaleDays+ days)" -Data $StaleAccounts -RowClass "warn"
    $body += Build-HtmlSection -Title "Disabled Accounts in Privileged Groups" -Data $PrivilegedDisabled -RowClass "risk"
    $body += Build-HtmlSection -Title "Passwords Expiring within $PasswordExpiryWarningDays Days" -Data $ExpiringPasswords -RowClass "warn"
    $body += Build-HtmlSection -Title "Empty Groups" -Data $EmptyGroups -RowClass "warn"

    $footnote = @"
<p class='footnote'>
Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") by ADAccountAudit.ps1. Read-only report - no changes were made to Active Directory.
Note: LastLogonTimestamp can lag up to 14 days across DC replication, so treat stale-account dates as approximate rather than exact.
</p>
"@

    $html = "<html><head><title>AD Account Audit</title>$style</head><body><h1>AD Account Audit Report</h1>$summary$body$footnote</body></html>"

    $htmlPath = Join-Path $Script:reportFolder "$($Script:reportBaseName).html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log -Message "Wrote HTML report: $htmlPath" -Level INFO
}

##################################################
# Main
##################################################

Write-Log -Message "=== ADAccountAudit starting ===" -Level INFO
Write-Log -Message "Parameters: StaleDays=$StaleDays, PasswordExpiryWarningDays=$PasswordExpiryWarningDays, PrivilegedGroups=$($PrivilegedGroups -join ', '), SearchBase=$SearchBase, IncludeDistributionGroups=$($IncludeDistributionGroups.IsPresent), LogRetentionDays=$LogRetentionDays" -Level INFO

Try {
    Remove-OldFiles -Path (Join-Path $OutputRoot "Logs") -RetentionDays $LogRetentionDays
    Remove-OldFiles -Path (Join-Path $OutputRoot "Reports") -RetentionDays $LogRetentionDays

    Install-RequiredModules

    if (-not (Test-Path $Script:reportFolder)) {
        New-Item -ItemType Directory -Path $Script:reportFolder -Force -ErrorAction Stop | Out-Null
    }

    Try {
        Get-ADDomain -ErrorAction Stop | Out-Null
    }
    Catch {
        Write-Log -Message "Could not contact a domain controller: $($_.Exception.Message). Check network connectivity and that this machine is domain-joined." -Level CRITICAL
    }

    $staleAccounts      = Get-StaleAccounts
    $privilegedDisabled = Get-DisabledPrivilegedAccounts
    $expiringPasswords  = Get-ExpiringPasswords
    $emptyGroups        = Get-EmptyGroups

    Export-AuditCsv -StaleAccounts $staleAccounts -PrivilegedDisabled $privilegedDisabled -ExpiringPasswords $expiringPasswords -EmptyGroups $emptyGroups
    Export-AuditHtml -StaleAccounts $staleAccounts -PrivilegedDisabled $privilegedDisabled -ExpiringPasswords $expiringPasswords -EmptyGroups $emptyGroups

    Write-Log -Message "=== ADAccountAudit completed successfully ===" -Level INFO
    exit 0
}
Catch {
    Write-Log -Message "Unhandled error: $($_.Exception.Message)" -Level CRITICAL
}