<#
    .SYNOPSIS
        Forces a Windows client to check in against its configured WSUS server,
        collecting diagnostic information and optionally remediating common
        synchronisation and installation errors automatically.

    .DESCRIPTION
        Collects the currently configured WSUS server/status server from Group
        Policy, verifies name resolution, network reachability, and (if HTTPS)
        certificate trust. Checks for a pending reboot, low disk space, and
        disabled prerequisite services. Attempts synchronisation against WSUS,
        retrying up to a configured number of times. Reviews update history for
        errors that occurred during this run and, if -AutomaticallyRemediate is
        set, attempts known fixes for recognised error codes before retrying
        synchronisation once more.

        Designed to run unattended, including via PowerShell remoting across
        many machines simultaneously, and via Scheduled Task. No interactive
        prompts. Writes an HTML report and CSV export per run, in addition to
        the log file and Application event log entries.

    .PARAMETER AutomaticallyRemediate
        If set, attempts to automatically fix recognised issues (disabled
        services, corrupted component store, stale caches, etc.) rather than
        only reporting them. Some detected issues (policy-managed settings)
        are never auto-remediated regardless of this switch, since doing so
        would override a deliberate administrative decision.

    .PARAMETER CustomLogPath
        Full path to the log file. Defaults to
        C:\Pickering-Cloud\Logs\WSUSClientSync\WSUSClientSync_<timestamp>.log
        under -OutputRoot.

    .PARAMETER OutputRoot
        Root folder for logs and reports. Default C:\Pickering-Cloud. Ignored
        for logging if -CustomLogPath is supplied, but still used for reports.

    .PARAMETER LogRetentionDays
        Number of days to retain log and report files before automatic
        cleanup. Default 30.

    .EXAMPLE
        .\WSUS-ClientSync.ps1

        Runs diagnostics and a sync attempt, reporting any issues found without
        changing anything.

    .EXAMPLE
        .\WSUS-ClientSync.ps1 -AutomaticallyRemediate -CustomLogPath D:\Logs\wsus.log

        Runs diagnostics, attempts automatic remediation of recognised issues,
        and retries synchronisation once afterward.

    .OUTPUTS
        None. Writes progress and results to the configured log file, the
        Application event log (source: "WSUS Client Sync Script"), and an
        HTML report + CSV export under $OutputRoot\Reports\WSUSClientSync.
        See the project README for the full event ID map.

    .NOTES
        Author: Bradley Pickering
        GitHub: https://github.com/Pickering-Cloud
        Requires: No special module dependencies beyond built-in Windows
        Update Agent COM APIs.
#>

##################################################
# Script Parameters
##################################################

[CmdletBinding(SupportsShouldProcess)]
param (
    [switch]$AutomaticallyRemediate,
    [string]$CustomLogPath,
    [string]$OutputRoot = "C:\Pickering-Cloud",
    [int]$LogRetentionDays = 30
)

##################################################
# Variables
##################################################
$Script:startTime = Get-Date
$Script:date = Get-Date -Format "yyyyMMdd_HHmmss"
[string]$Script:logPath = if ($CustomLogPath) { $CustomLogPath.Replace("/", "\") } else { Join-Path $OutputRoot "Logs\WSUSClientSync\WSUSClientSync_$($Script:date).log" }
[string]$Script:eventLogSource = "WSUS Client Sync Script"
[string]$Script:eventLogName = "Application"
[string]$Script:reportFolder = Join-Path $OutputRoot "Reports\WSUSClientSync"
[string]$Script:reportBaseName = "WSUSClientSync_$($Script:date)"
[int]$Script:minimumRequiredGB = 10
$Script:syncAttempts = 3
$Script:updateErrors = @()
$Script:serviceStates = @()
$Script:actionsTaken = @()
$Script:sfcAlreadyRun = $false
$Script:dismAlreadyRun = $false
$Script:sdFolderResetAlreadyRun = $false
$Script:bitsQueueResetAlreadyRun = $false
$Script:bitsQueueFileResetAlreadyRun = $false

##################################################
# Logging
##################################################

function Configure-LogPath {
    <#
    .SYNOPSIS
        Ensures the log directory exists.
    .DESCRIPTION
        Checks whether the parent directory of $Script:logPath exists, creating
        it if necessary. Called internally by Write-Log before every write, so
        the log directory is created on demand rather than requiring manual
        setup.
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
        Appends an entry to the log file at $Script:logPath and echoes it to
        the console. CRITICAL-level messages exit the script with code 1 after
        being logged, regardless of whether the log file itself could be
        written, so a broken logging path can never silently swallow a fatal
        error. Every level is always written - there is no severity threshold
        to configure, so DEBUG-level entries appear in the log on every run.
    .PARAMETER Message
        The text to log.
    .PARAMETER Level
        Severity of the entry. One of INFO, DEBUG, WARN, ERROR, CRITICAL.
        Defaults to INFO. CRITICAL causes the script to exit after logging.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")]
        [string]$Level = "INFO"
    )
    $prefix = "[$Level]"

    if ($Level -eq "DEBUG" -and $DebugPreference -eq "SilentlyContinue") {
        return
    }

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

# Configures Event Viewer Source if it doesn't exist
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Script:eventLogSource)) {
        New-EventLog -LogName $Script:eventLogName -Source $Script:eventLogSource
    }
}
catch {
    Write-Log -Level WARN -Message "Could not register event log source '$Script:eventLogSource': $($_.Exception.Message). Event log writes will fail until this is resolved (requires an elevated session)."
}

# Writes to Event Log
function Write-LogEvent {
    <#
    .SYNOPSIS
        Writes an entry to the Windows Application Event Log.
    .DESCRIPTION
        Wraps Write-EventLog, writing under the script's registered event
        source (see the event source registration above). Used for the subset
        of conditions worth surfacing to centralised monitoring, distinct from
        the full-fidelity file log written via Write-Log.
    .PARAMETER logSource
        The event source to write under. Defaults to $Script:eventLogSource.
    .PARAMETER logName
        The event log to write to (e.g. "Application"). Defaults to
        $Script:eventLogName.
    .PARAMETER message
        The text of the event.
    .PARAMETER eventID
        The event ID to log. See the project README for the full event ID map.
    .PARAMETER entryType
        The event's severity: Error, Warning, Information, SuccessAudit, or
        FailureAudit.
    .EXAMPLE
        Write-LogEvent -eventID 1007 -entryType Error -message "WSUS sync failed after 3 attempt(s)."

        Writes an Error-level event under the script's registered source.
    .OUTPUTS
        None. Writes to the Application event log as a side effect.
    #>
    [CmdletBinding()]
    param (
        [string]$logSource = $Script:eventLogSource,
        [string]$logName = $Script:eventLogName,
        [Parameter(Mandatory)]
        [string]$message,
        [Parameter(Mandatory)]
        [int]$eventID,
        [Parameter(Mandatory)]
        [System.Diagnostics.EventLogEntryType]$entryType
    )
    Write-EventLog -LogName $logName -Source $logSource -EntryType $entryType -Category 0 -EventId $eventID -Message $message
}

Write-Log -Level DEBUG -Message "Logging has been configured"
Write-Log -Level DEBUG -Message "logPath=$Script:logPath; eventLogSource=$Script:eventLogSource; eventLogName=$Script:eventLogName; reportFolder=$Script:reportFolder"
Write-Log -Level INFO -Message "Script is running"

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
        WARN and continues, since a locked file shouldn't stop the run.
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
            Write-Log -Level INFO -Message "Removed old file beyond ${RetentionDays}-day retention: $($file.FullName)"
        }
        Catch {
            Write-Log -Level WARN -Message "Failed to remove old file $($file.FullName): $($_.Exception.Message)"
        }
    }
}

Remove-OldFiles -Path (Join-Path $OutputRoot "Logs\WSUSClientSync") -RetentionDays $LogRetentionDays
Remove-OldFiles -Path $Script:reportFolder -RetentionDays $LogRetentionDays

########## Collate Existing Configuration ##########

Write-Log -Level DEBUG -Message "Beginning configuration collection"

# WSUS server info
[System.Uri]$initialWUServer = (Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -ErrorAction SilentlyContinue).WUServer
[System.Uri]$initialWUStatusServer = (Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -ErrorAction SilentlyContinue).WUStatusServer
Write-Log -Level DEBUG -Message "Pre-gpupdate WUServer=$initialWUServer; WUStatusServer=$initialWUStatusServer"

Write-Log -Level DEBUG -Message "Forcing Group Policy update"
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Force Group Policy update (gpupdate /force)')) {
    $groupPolicyResult = gpupdate /force /target:computer 2>&1
    Write-Log -Level DEBUG -Message "gpupdate output: $($groupPolicyResult -join ' | ')"
    if ($groupPolicyResult -match 'failed|error') {
        Write-Log -Level WARN -Message "gpupdate output suggests a possible failure, review debug log output above."
    }
}

[System.Uri]$WUServer = (Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -ErrorAction SilentlyContinue).WUServer
[System.Uri]$WUStatusServer = (Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -ErrorAction SilentlyContinue).WUStatusServer
Write-Log -Level DEBUG -Message "Post-gpupdate WUServer=$WUServer; WUStatusServer=$WUStatusServer"

if ($initialWUServer -ne $WUServer) {
    Write-Log -Level INFO -Message "Group Policy update amended configured WSUS server"
}
if ($initialWUStatusServer -ne $WUStatusServer) {
    Write-Log -Level INFO -Message "Group Policy update amended configured WSUS Status server"
}

if ($null -eq $WUServer) {
    Write-Log -Level CRITICAL -Message "No WSUS server configured - please review Group Policy/Registry configuration"
    Write-LogEvent -eventID 1002 -entryType Error -message "No WSUS server configured - please review Group Policy/Registry configuration"
}
if ($null -eq $WUStatusServer) {
    Write-Log -Level CRITICAL -Message "No WSUS Status server configured - please review Group Policy/Registry configuration"
    Write-LogEvent -eventID 1003 -entryType Error -message "No WSUS Status server configured - please review Group Policy/Registry configuration"
}

Write-Log -Level DEBUG -Message "Configured WSUS server is $WUServer. Configured WSUS Status server is $WUStatusServer"

    ########## Test Configurations ##########

Write-Log -Level DEBUG -Message "Beginning configuration testing"

# Attempt to resolve DNS name
Write-Log -Level DEBUG -Message "Attempting to resolve DNS name"
$parsedIP = $null
if ([System.Net.IPAddress]::TryParse($WUServer.Host, [ref]$parsedIP)) {
    Write-Log -Level INFO -Message "WSUS server is configured as an IP address"
}
else {
    try {
        $dnsCheck = Resolve-DnsName -Name $WUServer.Host -ErrorAction Stop
        Write-Log -Level DEBUG -Message "DNS resolution succeeded"
        Write-Log -Level DEBUG -Message "DNS resolution result: $($dnsCheck | Out-String)"
    }
    catch {
        Write-Log -Level CRITICAL -Message "Unable to resolve DNS name for WSUS server: $($WUServer.Host). $($_.Exception.Message)"
        Write-LogEvent -eventID 1004 -entryType Error -message "Unable to resolve DNS name for WSUS server: $($WUServer.Host)"
    }
}

# Test network connectivity
Write-Log -Level DEBUG -Message "Testing network connections"
$pingCheck = Test-Connection -ComputerName $WUServer.Host -Quiet -ErrorAction SilentlyContinue
$portCheck = Test-NetConnection -ComputerName $WUServer.Host -Port $WUServer.Port -InformationLevel Quiet -ErrorAction SilentlyContinue
Write-Log -Level DEBUG -Message "pingCheck=$pingCheck; portCheck=$portCheck"

if (-not $portCheck) {
    Write-Log -Level CRITICAL -Message "Unable to reach WSUS server on port $($WUServer.Port)."
    Write-LogEvent -eventID 1005 -entryType Error -message "Unable to reach WSUS server on port $($WUServer.Port)."
}
if (-not $pingCheck) {
    Write-Log -Level WARN -Message "ICMP ping to WSUS server failed, this may be normal if ICMP is blocked by firewall policy."
}

    # Check IIS certificate is trusted
    $certTrustResult = [PSCustomObject]@{
        IsTrusted   = $true
        Subject     = $null
        Issuer      = $null
        Thumbprint  = $null
        NotAfter    = $null
        ChainStatus = @()
    }

if ($WUServer.Scheme -eq 'https') {
    Write-Log -Level DEBUG -Message "Checking for certificate trust"
    $tcpClient = $null
    $sslStream = $null
    $Script:capturedCert = $null

        try {
            $tcpClient = [System.Net.Sockets.TcpClient]::new()
            $tcpClient.Connect($WUServer.Host, $WUServer.Port)

            $validationCallback = {
                param($senderObj, $certificate, $chain, $sslPolicyErrors)
                $script:capturedCert = $certificate
                return $true
            }

            $sslStream = [System.Net.Security.SslStream]::new(
                $tcpClient.GetStream(),
                $false,
                $validationCallback
            )

            $sslStream.AuthenticateAsClient($WUServer.Host)

            if (-not $script:capturedCert) {
                throw "No certificate was presented by $($WUServer.Host):$($WUServer.Port)."
            }

            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($script:capturedCert)

            $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
            $chain.ChainPolicy.RevocationMode = 'NoCheck'
            $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

            $isValid = $chain.Build($cert)

        $certTrustResult = [PSCustomObject]@{
            IsTrusted   = $isValid
            Subject     = $cert.Subject
            Issuer      = $cert.Issuer
            Thumbprint  = $cert.Thumbprint
            NotAfter    = $cert.NotAfter
            ChainStatus = $chain.ChainStatus | ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }
        }
    }
    catch {
        $certTrustResult = [PSCustomObject]@{
            IsTrusted   = $false
            Subject     = $null
            Issuer      = $null
            Thumbprint  = $null
            NotAfter    = $null
            ChainStatus = @("Connection or handshake failed: $($_.Exception.Message)")
        }
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Dispose() }
    }
}
else {
    Write-Log -Level DEBUG -Message "WUServer $WUServer is not using HTTPS, skipping certificate trust check."
}

if ($certTrustResult.IsTrusted) {
    Write-Log -Level DEBUG -Message "WSUS server certificate trust check passed (or not applicable)."
}
else {
    Write-Log -Level ERROR -Message "WSUS server certificate is not trusted. Issuer: $($certTrustResult.Issuer). Detail: $($certTrustResult.ChainStatus -join ' | ')"
    Write-LogEvent -eventID 1006 -entryType Warning -message "WSUS server certificate is not trusted. Issuer: $($certTrustResult.Issuer)"
}

# Check for pending reboot
Write-Log -Level DEBUG -Message "Testing if machine is in pending reboot state"
$rebootPending = $false
$rebootReasons = @()

    if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $rebootPending = $true
        $rebootReasons += "Component Based Servicing"
    }

    if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $rebootPending = $true
        $rebootReasons += "Windows Update"
    }

    $pfro = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    if ($pfro) {
        $rebootPending = $true
        $rebootReasons += "Pending File Rename Operations"
    }

    $activeName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue).ComputerName
    $pendingName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue).ComputerName
    if ($activeName -and $pendingName -and $activeName -ne $pendingName) {
        $rebootPending = $true
        $rebootReasons += "Pending computer rename"
    }

    if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Name "JoinDomain" -ErrorAction SilentlyContinue) {
        $rebootPending = $true
        $rebootReasons += "Pending domain join"
    }
    if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Name "AvoidSpnSet" -ErrorAction SilentlyContinue) {
        $rebootPending = $true
        $rebootReasons += "Pending domain rename"
    }

    $ccmClientSDK = Get-CimInstance -Namespace "ROOT\ccm\ClientSDK" -ClassName CCM_ClientUtilities -ErrorAction SilentlyContinue
    if ($ccmClientSDK) {
        $ccmResult = Invoke-CimMethod -Namespace "ROOT\ccm\ClientSDK" -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction SilentlyContinue
        if ($ccmResult -and ($ccmResult.RebootPending -or $ccmResult.IsHardRebootPending)) {
            $rebootPending = $true
            $rebootReasons += "SCCM client"
        }
    }

if ($rebootPending) {
    Write-Log -Level WARN -Message "Reboot pending: $($rebootReasons -join ', ')"
}
else {
    Write-Log -Level DEBUG -Message "No reboot pending."
}

# Check for available space on system drive
Write-Log -Level DEBUG -Message "Checking available space on system drive"
$systemDrive = $env:SystemDrive.TrimEnd(':')
$totalSpaceGB = $null
$freeSpaceGB = $null

try {
    $diskInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive`:'" -ErrorAction Stop
    $totalSpaceGB = [math]::Round($diskInfo.Size / 1GB, 2)
    $freeSpaceGB = [math]::Round($diskInfo.FreeSpace / 1GB, 2)
    Write-Log -Level DEBUG -Message "Raw disk info: Size=$($diskInfo.Size) FreeSpace=$($diskInfo.FreeSpace)"

    if ($freeSpaceGB -lt $Script:minimumRequiredGB) {
        Write-Log -Level WARN -Message "Low disk space on $systemDrive`: $freeSpaceGB GB free out of $totalSpaceGB GB. Minimum recommended: $Script:minimumRequiredGB GB."
    }
    else {
        Write-Log -Level INFO -Message "$systemDrive`: $freeSpaceGB GB free out of $totalSpaceGB GB."
    }
}
catch {
    Write-Log -Level ERROR -Message "Failed to query disk space for $systemDrive`: $($_.Exception.Message)"
}

    # Service state
    $requiredServices = @(
        "wuauserv",
        "bits",
        "cryptsvc"
    )

Write-Log -Level DEBUG -Message "Ensuring required services are not disabled"
foreach ($service in $requiredServices) {
    $svc = Get-Service -Name $service
    Write-Log -Level DEBUG -Message "Service '$service': StartType=$($svc.StartType), Status=$($svc.Status)"

    $Script:serviceStates += [PSCustomObject]@{
        Service   = $service
        StartType = $svc.StartType
        Status    = $svc.Status
    }

    if ($svc.StartType -eq "Disabled") {
        if ($AutomaticallyRemediate) {
            if ($PSCmdlet.ShouldProcess($service, 'Set service startup type to Manual')) {
                try {
                    Set-Service -Name $service -StartupType Manual -ErrorAction Stop
                    Write-Log -Level WARN -Message "Service '$service' was Disabled, set to Manual."
                    $Script:actionsTaken += "Set service '$service' startup type from Disabled to Manual."
                }
                catch {
                    Write-Log -Level ERROR -Message "Failed to change startup type for '$service': $($_.Exception.Message)"
                }
            }
        }
        else {
            Write-Log -Level WARN -Message "Service '$service' is Disabled. Run with -AutomaticallyRemediate to fix automatically."
        }
    }
}

$wuauservStatus = (Get-Service -Name "wuauserv").Status
if ($wuauservStatus -ne "Running") {
    if ($AutomaticallyRemediate) {
        if ($PSCmdlet.ShouldProcess("wuauserv", 'Start service')) {
            try {
                Start-Service -Name "wuauserv" -ErrorAction Stop
                Write-Log -Level WARN -Message "wuauserv was not running - service started"
                $Script:actionsTaken += "Started wuauserv service (was not running)."
            }
            catch {
                Write-Log -Level ERROR -Message "wuauserv was not running - unable to start service: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Log -Level WARN -Message "wuauserv is not running. Run with -AutomaticallyRemediate to start it automatically."
    }
}
else {
    Write-Log -Level DEBUG -Message "wuauserv is already running."
}

    ########## Sync Attempt Logic ##########
    function Invoke-SyncAttempt {
        <#
        .SYNOPSIS
            Attempts to trigger a Windows Update synchronisation via all available mechanisms.
        .DESCRIPTION
            Triggers detection/sync via the Windows Update Agent COM API, UsoClient,
            and legacy wuauclt (in that order, each independently wrapped so one
            failing doesn't prevent the others from running), waits, then checks
            whether LastSuccessTime indicates a genuinely recent successful
            detection.
        .OUTPUTS
            System.Boolean. $true if a successful detection was recorded within
            the last 5 minutes, otherwise $false.
        .EXAMPLE
            Invoke-SyncAttempt

            Triggers a synchronisation attempt and returns whether it succeeded.
        #>
        [CmdletBinding(SupportsShouldProcess)]
        param()

    if ($PSCmdlet.ShouldProcess('Windows Update', 'Trigger synchronisation attempt')) {
        if ($autoUpdate) {
            try {
                $autoUpdate.DetectNow()
                Write-Log -Level DEBUG -Message "COM API DetectNow triggered."
            }
            catch {
                Write-Log -Level WARN -Message "COM API DetectNow failed: $($_.Exception.Message)"
            }
        }
        try {
            $usoResult = & "$env:SystemRoot\System32\UsoClient.exe" ScanInstallWait 2>&1
            Write-Log -Level DEBUG -Message "UsoClient ScanInstallWait output: $($usoResult -join ' ')"
        }
        catch {
            Write-Log -Level WARN -Message "UsoClient ScanInstallWait failed: $($_.Exception.Message)"
        }
        try {
            & "$env:SystemRoot\System32\wuauclt.exe" /detectnow /reportnow
            Write-Log -Level DEBUG -Message "wuauclt /detectnow /reportnow invoked."
        }
        catch {
            Write-Log -Level WARN -Message "wuauclt failed: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 60
        $lastSuccess = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -Name "LastSuccessTime" -ErrorAction SilentlyContinue).LastSuccessTime
        Write-Log -Level DEBUG -Message "LastSuccessTime read as: $lastSuccess"
        return [bool]($lastSuccess -and ((Get-Date) - [DateTime]$lastSuccess).TotalMinutes -le 5)
    }

        return $false
    }

    ########## Attempt Synchronisation ##########
    [int]$syncs = 0
    $syncSucceeded = $false

try {
    $autoUpdate = New-Object -ComObject "Microsoft.Update.AutoUpdate" -ErrorAction Stop
}
catch {
    Write-Log -Level ERROR -Message "Failed to create Microsoft.Update.AutoUpdate COM object: $($_.Exception.Message)"
}

do {
    Write-Log -Level DEBUG -Message "Starting sync - attempt $($syncs + 1)"
    $syncSucceeded = Invoke-SyncAttempt
    $syncs += 1
    Write-Log -Level DEBUG -Message "Sync $syncs finished. Success: $syncSucceeded"
}
until ($syncSucceeded -or $syncs -ge $Script:syncAttempts)

if ($syncSucceeded) {
    Write-Log -Level INFO -Message "Sync succeeded after $syncs attempt(s)."
}
else {
    Write-Log -Level ERROR -Message "Sync did not succeed after $syncs attempt(s)."
    Write-LogEvent -eventID 1007 -entryType Error -message "WSUS sync failed after $syncs attempt(s)."
}

########## Identify Errors ##########
Write-Log -Level DEBUG -Message "Reviewing update history for errors since $Script:startTime"

try {
    $updateSession = New-Object -ComObject "Microsoft.Update.Session" -ErrorAction Stop
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $historyCount = $updateSearcher.GetTotalHistoryCount()
    Write-Log -Level DEBUG -Message "Total update history entries on this machine: $historyCount"

        if ($historyCount -gt 0) {
            $history = $updateSearcher.QueryHistory(0, $historyCount)

        $Script:updateErrors = $history | Where-Object {
            $_.Date -ge $Script:startTime -and $_.ResultCode -in @(3, 4, 5)
        } | ForEach-Object {
            [PSCustomObject]@{
                Title      = $_.Title
                Date       = $_.Date
                Operation  = switch ($_.Operation) { 1 { "Installation" } 2 { "Uninstallation" } default { "Unknown" } }
                ResultCode = switch ($_.ResultCode) { 3 { "SucceededWithErrors" } 4 { "Failed" } 5 { "Aborted" } default { "Unknown" } }
                HResult    = '0x{0:X8}' -f $_.HResult
            }
        }
    }
    else {
        Write-Log -Level DEBUG -Message "No update history entries found on this machine."
    }
}
catch {
    Write-Log -Level ERROR -Message "Failed to query update history: $($_.Exception.Message)"
}

if ($Script:updateErrors.Count -gt 0) {
    foreach ($err in $Script:updateErrors) {
        Write-Log -Level ERROR -Message "Update error: '$($err.Title)' - $($err.Operation) $($err.ResultCode) ($($err.HResult)) at $($err.Date)"
        Write-LogEvent -eventID 1008 -entryType Error -message "Update error: '$($err.Title)' - $($err.ResultCode) ($($err.HResult))"
    }
}
else {
    Write-Log -Level INFO -Message "No update install/uninstall errors found since script start ($Script:startTime)."
}

########## Attempt Remediations ##########
Write-Log -Level DEBUG -Message "Beginning remediation phase (AutomaticallyRemediate=$($AutomaticallyRemediate.IsPresent))"

    # Repair actions - called by multiple repair functions

    function Invoke-SFCScanOnce {
        <#
        .SYNOPSIS
            Runs sfc /scannow once per script execution.
        .DESCRIPTION
            Runs the System File Checker to repair corrupted system files, but only
            once per session, tracked via $Script:sfcAlreadyRun, since this is a
            genuinely expensive operation that multiple Repair-<code> functions may
            otherwise trigger redundantly if the same underlying fix applies to
            several detected error codes.
        .OUTPUTS
            None. Writes sfc's output to the log file as a side effect.
        .EXAMPLE
            Invoke-SFCScanOnce

            Runs sfc /scannow if it hasn't already run this session.
        #>
        [CmdletBinding(SupportsShouldProcess)]
        param()

    if ($Script:sfcAlreadyRun) {
        Write-Log -Level DEBUG -Message "sfc /scannow already run this session, skipping."
        return
    }

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Run sfc /scannow')) {
        Write-Log -Level DEBUG -Message "Running sfc /scannow."
        $sfcOutput = sfc /scannow 2>&1
        Write-Log -Level DEBUG -Message "sfc /scannow output: $($sfcOutput -join ' ')"
        $Script:sfcAlreadyRun = $true
        $Script:actionsTaken += "Ran sfc /scannow."
    }
}

    function Invoke-DISMRestoreHealthOnce {
        <#
        .SYNOPSIS
            Runs DISM /Online /Cleanup-Image /RestoreHealth once per script execution.
        .DESCRIPTION
            Runs DISM's component store repair, but only once per session, tracked
            via $Script:dismAlreadyRun, since this is a genuinely expensive
            operation that multiple Repair-<code> functions may otherwise trigger
            redundantly if the same underlying fix applies to several detected
            error codes.
        .OUTPUTS
            None. Writes DISM's output to the log file as a side effect.
        .EXAMPLE
            Invoke-DISMRestoreHealthOnce

            Runs DISM /Online /Cleanup-Image /RestoreHealth if it hasn't already
            run this session.
        #>
        [CmdletBinding(SupportsShouldProcess)]
        param()

    if ($Script:dismAlreadyRun) {
        Write-Log -Level DEBUG -Message "DISM /RestoreHealth already run this session, skipping."
        return
    }

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Run DISM /Online /Cleanup-Image /RestoreHealth')) {
        Write-Log -Level DEBUG -Message "Running DISM /Online /Cleanup-Image /RestoreHealth."
        $dismOutput = DISM /Online /Cleanup-Image /RestoreHealth 2>&1
        Write-Log -Level DEBUG -Message "DISM output: $($dismOutput -join ' ')"
        $Script:dismAlreadyRun = $true
        $Script:actionsTaken += "Ran DISM /Online /Cleanup-Image /RestoreHealth."
    }
}

    function Invoke-ResetFolderCache {
        <#
        .SYNOPSIS
            Resets the SoftwareDistribution and catroot2 folders, once per script execution.
        .DESCRIPTION
            Stops wuauserv, bits, and cryptsvc, renames SoftwareDistribution and
            catroot2 to .old backups (clearing any existing backup from a previous
            run first), then restarts the services regardless of whether the
            rename succeeded, via a finally block, so a failed reset never leaves
            Windows Update services stopped. Only runs once per session, tracked
            via $Script:sdFolderResetAlreadyRun.
        .OUTPUTS
            None. Renames folders on disk and logs the outcome of each step.
        .EXAMPLE
            Invoke-ResetFolderCache

            Resets the SoftwareDistribution and catroot2 folders if this hasn't
            already run this session.
        #>
        [CmdletBinding(SupportsShouldProcess)]
        param()

    if ($Script:sdFolderResetAlreadyRun) {
        Write-Log -Level DEBUG -Message "SoftwareDistribution/catroot2 reset already run this session, skipping."
        return
    }

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Reset SoftwareDistribution and catroot2 folders')) {
        Write-Log -Level INFO -Message "Resetting SoftwareDistribution and catroot2 folders."
        $sdServices = @("wuauserv", "bits", "cryptsvc")
        $foldersToReset = @(
            @{ Path = "$env:SystemRoot\SoftwareDistribution"; BackupName = "SoftwareDistribution.old" },
            @{ Path = "$env:SystemRoot\System32\catroot2"; BackupName = "catroot2.old" }
        )
        try {
            foreach ($service in $sdServices) {
                try {
                    Stop-Service -Name $service -Force -ErrorAction Stop
                    Write-Log -Level DEBUG -Message "Stopped service '$service'."
                }
                catch {
                    Write-Log -Level WARN -Message "Failed to stop service '$service': $($_.Exception.Message)"
                }
            }
            foreach ($folder in $foldersToReset) {
                $backupPath = Join-Path -Path (Split-Path -Path $folder.Path -Parent) -ChildPath $folder.BackupName
                if (Test-Path -Path $backupPath) {
                    Write-Log -Level DEBUG -Message "Removing existing backup at '$backupPath' from a previous run."
                    Remove-Item -Path $backupPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                if (Test-Path -Path $folder.Path) {
                    try {
                        Rename-Item -Path $folder.Path -NewName $folder.BackupName -ErrorAction Stop
                        Write-Log -Level INFO -Message "Renamed '$($folder.Path)' to '$($folder.BackupName)'."
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Failed to rename '$($folder.Path)': $($_.Exception.Message)"
                    }
                }
                else {
                    Write-Log -Level WARN -Message "Folder not found at '$($folder.Path)', nothing to rename."
                }
            }
        }
        finally {
            foreach ($service in $sdServices) {
                try {
                    Start-Service -Name $service -ErrorAction Stop
                    Write-Log -Level DEBUG -Message "Started service '$service'."
                }
                catch {
                    Write-Log -Level ERROR -Message "Failed to restart service '$service': $($_.Exception.Message). This service may need manual attention."
                    Write-LogEvent -eventID 1015 -entryType Error -message "Failed to restart service '$service' after remediation. Manual attention required."
                }
            }
        }
        $Script:sdFolderResetAlreadyRun = $true
        $Script:actionsTaken += "Reset SoftwareDistribution and catroot2 folders."
    }
}

    function Invoke-BitsQueueReset {
        <#
        .SYNOPSIS
            Removes stuck or errored jobs from the BITS transfer queue, once per script execution.
        .DESCRIPTION
            Queries all BITS transfer jobs (all users, requires elevation) and
            removes any in an Error, TransientError, or Suspended state. If the
            query itself fails (the API doesn't respond), escalates to the more
            invasive Invoke-BitsQueueFileReset. Only runs once per session, tracked
            via $Script:bitsQueueResetAlreadyRun.
        .OUTPUTS
            None. Removes problem BITS jobs and logs the outcome.
        .EXAMPLE
            Invoke-BitsQueueReset

            Checks the BITS transfer queue and removes any problem jobs, if this
            hasn't already run this session.
        #>
        [CmdletBinding(SupportsShouldProcess)]
        param()

    if ($Script:bitsQueueResetAlreadyRun) {
        Write-Log -Level DEBUG -Message "BITS queue reset already run this session, skipping."
        return
    }

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Check and reset BITS transfer queue')) {
        Write-Log -Level INFO -Message "Checking BITS transfer queue for stuck or errored jobs."
        try {
            $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction Stop
            $problemJobs = $bitsJobs | Where-Object { $_.JobState -in @('Error', 'TransientError', 'Suspended') }
            if ($problemJobs) {
                foreach ($job in $problemJobs) {
                    Write-Log -Level WARN -Message "Removing BITS job '$($job.DisplayName)' (State: $($job.JobState))."
                    try {
                        Remove-BitsTransfer -BitsJob $job -ErrorAction Stop
                        $Script:actionsTaken += "Removed BITS job '$($job.DisplayName)' (State: $($job.JobState))."
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Failed to remove BITS job '$($job.DisplayName)': $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-Log -Level DEBUG -Message "No problem BITS jobs found in queue."
            }
        }
        catch {
            Write-Log -Level WARN -Message "Failed to query BITS transfer queue via API: $($_.Exception.Message). Escalating to file-level reset."
            Invoke-BitsQueueFileReset
        }
        $Script:bitsQueueResetAlreadyRun = $true
    }
}

    function Invoke-BitsQueueFileReset {
        <#
        .SYNOPSIS
            Performs a file-level reset of the BITS transfer queue, once per script execution.
        .DESCRIPTION
            More invasive fallback for when the API-based approach
            (Invoke-BitsQueueReset) can't run at all. Stops the BITS service,
            deletes the queue database files directly, and restarts the service
            regardless of whether the deletion succeeded, via a finally block, so
            a failed reset never leaves BITS stopped. Only runs once per session,
            tracked via $Script:bitsQueueFileResetAlreadyRun.
        .OUTPUTS
            None. Deletes BITS queue files on disk and logs the outcome.
        .EXAMPLE
            Invoke-BitsQueueFileReset

            Performs a file-level BITS queue reset if this hasn't already run
            this session.
        #>
        [CmdletBinding(SupportsShouldProcess)]
        param()

    if ($Script:bitsQueueFileResetAlreadyRun) {
        Write-Log -Level DEBUG -Message "BITS queue file reset already run this session, skipping."
        return
    }

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Perform file-level BITS queue reset')) {
        Write-Log -Level DEBUG -Message "Performing file-level BITS queue reset."
        $downloaderPath = "$env:ProgramData\Microsoft\Network\Downloader"
        try {
            Stop-Service -Name bits -Force -ErrorAction Stop
            Get-ChildItem -Path $downloaderPath -Filter "qmgr*" -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Log -Level WARN -Message "Removing BITS queue file: $($_.Name)"
                Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log -Level ERROR -Message "File-level BITS queue reset failed: $($_.Exception.Message)"
        }
        finally {
            try {
                Start-Service -Name bits -ErrorAction Stop
            }
            catch {
                Write-Log -Level ERROR -Message "Failed to restart BITS service: $($_.Exception.Message). This service may need manual attention."
                Write-LogEvent -eventID 1015 -entryType Error -message "Failed to restart BITS service after remediation. Manual attention required."
            }
        }
        $Script:bitsQueueFileResetAlreadyRun = $true
        $Script:actionsTaken += "Performed file-level BITS queue reset."
    }
}

    # Error code repairs

    function Repair-8000FFFF {
        <#
        .SYNOPSIS
            Remediation for error code 0x8000FFFF (generic unexpected error).
        .DESCRIPTION
            Attempts a general component repair by running DISM /RestoreHealth
            followed by sfc /scannow, since 0x8000FFFF (E_UNEXPECTED) is too
            generic to diagnose more specifically. Delegates to the shared,
            idempotent Invoke-DISMRestoreHealthOnce and Invoke-SFCScanOnce
            functions, which handle their own ShouldProcess gating.
        .OUTPUTS
            None. Logs the remediation attempt and delegates to shared repair actions.
        .EXAMPLE
            Repair-8000FFFF

            Attempts a DISM and SFC repair for a generic unexpected error.
        #>
        [CmdletBinding()]
        param()

    Write-Log -Level INFO -Message "Repair-8000FFFF: generic unexpected error, attempting component repair."
    Write-LogEvent -eventID 1009 -entryType Warning -message "Repair-8000FFFF invoked: generic unexpected error."
    Invoke-DISMRestoreHealthOnce
    Invoke-SFCScanOnce
}

    function Repair-800F0831 {
        <#
        .SYNOPSIS
            Remediation for error code 0x800F0831 (component store corruption).
        .DESCRIPTION
            Attempts a component store repair by running DISM /RestoreHealth
            followed by sfc /scannow, per CBS.log indicating WinSxS corruption.
            Delegates to the shared, idempotent Invoke-DISMRestoreHealthOnce and
            Invoke-SFCScanOnce functions, which handle their own ShouldProcess
            gating.
        .OUTPUTS
            None. Logs the remediation attempt and delegates to shared repair actions.
        .EXAMPLE
            Repair-800F0831

            Attempts a DISM and SFC repair for detected component store corruption.
        #>
        [CmdletBinding()]
        param()

    Write-Log -Level INFO -Message "Repair-800F0831: component store corruption detected, attempting repair."
    Write-LogEvent -eventID 1010 -entryType Warning -message "Repair-800F0831 invoked: component store corruption."
    Invoke-DISMRestoreHealthOnce
    Invoke-SFCScanOnce
}

    function Repair-80244022 {
        <#
        .SYNOPSIS
            Remediation for error code 0x80244022 (WSUS server reported overloaded/unavailable).
        .DESCRIPTION
            Resets local caches that can help when the WSUS server itself reports
            being temporarily overloaded (WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL),
            per Microsoft's own guidance for this status code. Delegates to the
            shared, idempotent Invoke-ResetFolderCache and Invoke-BitsQueueReset
            functions, which handle their own ShouldProcess gating.
        .OUTPUTS
            None. Logs the remediation attempt and delegates to shared repair actions.
        .EXAMPLE
            Repair-80244022

            Resets the SoftwareDistribution/catroot2 folders and BITS queue in
            response to a WSUS server overloaded/unavailable error.
        #>
        [CmdletBinding()]
        param()

    Write-Log -Level INFO -Message "Repair-80244022: WSUS server reported overloaded/unavailable, resetting local cache."
    Write-LogEvent -eventID 1011 -entryType Warning -message "Repair-80244022 invoked: WSUS server overloaded/unavailable."
    Invoke-ResetFolderCache
    Invoke-BitsQueueReset
}

    function Repair-80072EE2 {
        <#
        .SYNOPSIS
            Remediation for error code 0x80072EE2 (timeout reaching WSUS server).
        .DESCRIPTION
            This error typically indicates a network, firewall, or WSUS server
            load issue rather than something locally repairable, so no component
            repair is attempted. Clears the local DNS client cache in case of
            stale resolution, then re-checks port connectivity and logs the
            result for investigation.
        .OUTPUTS
            None. Clears the DNS client cache and logs the outcome.
        .EXAMPLE
            Repair-80072EE2

            Clears the DNS cache and re-checks connectivity to the configured
            WSUS server following a timeout error.
        #>
        [CmdletBinding(SupportsShouldProcess)]
        param()

    Write-Log -Level WARN -Message "Repair-80072EE2: timeout reaching WSUS server. This is typically network/firewall/server-load related, not locally repairable."

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Clear DNS client cache')) {
        Clear-DnsClientCache
        $Script:actionsTaken += "Cleared DNS client cache (in response to 0x80072EE2)."
    }

    $retryPortCheck = Test-NetConnection -ComputerName $WUServer.Host -Port $WUServer.Port -InformationLevel Quiet -ErrorAction SilentlyContinue
    Write-Log -Level INFO -Message "Retry port check result: $retryPortCheck"
    Write-LogEvent -eventID 1012 -entryType Warning -message "Timeout reaching WSUS server, may require network/firewall investigation."
}

    function Repair-80072EE5 {
        <#
        .SYNOPSIS
            Remediation for error code 0x80072EE5 (malformed WSUS URL).
        .DESCRIPTION
            This error typically indicates a trailing slash or other malformation
            in the WUServer registry value, which is a GPO-managed policy setting.
            Deliberately does not modify the value automatically, since doing so
            would override a deliberate administrative decision, logs the issue
            with guidance instead.
        .OUTPUTS
            None. Logs the issue for manual policy correction.
        .EXAMPLE
            Repair-80072EE5

            Logs guidance for correcting a malformed WSUS server URL in Group
            Policy.
        #>
        [CmdletBinding()]
        param()

    Write-Log -Level ERROR -Message "Repair-80072EE5: WUServer URL appears malformed (check for a trailing slash). Current value: $($WUServer.OriginalString). This is a policy-managed setting and will not be modified automatically."
    Write-LogEvent -eventID 1013 -entryType Error -message "WSUS server URL is malformed, requires GPO/policy correction."
}

    function Repair-8024002E {
        <#
        .SYNOPSIS
            Remediation for error code 0x8024002E (Windows Update disabled by policy).
        .DESCRIPTION
            This error indicates Windows Update access has been intentionally
            disabled via Group Policy. Deliberately does not override this
            automatically, since doing so would reverse a deliberate
            administrative decision, logs the issue with guidance instead.
        .OUTPUTS
            None. Logs the issue for manual policy review.
        .EXAMPLE
            Repair-8024002E

            Logs guidance noting that Windows Update access is disabled by policy
            and will not be overridden.
        #>
        [CmdletBinding()]
        param()

    Write-Log -Level ERROR -Message "Repair-8024002E: Windows Update access is disabled by policy on this machine. This will not be overridden automatically."
    Write-LogEvent -eventID 1014 -entryType Error -message "Windows Update access disabled by policy on $env:COMPUTERNAME."
}

if ($AutomaticallyRemediate) {
    $uniqueErrorCodes = $Script:updateErrors.HResult | Select-Object -Unique
    Write-Log -Level DEBUG -Message "Unique error codes to remediate: $($uniqueErrorCodes -join ', ')"

        foreach ($hexErr in $uniqueErrorCodes) {
            $codeSuffix = $hexErr -replace '^0x', ''
            $repairFunctionName = "Repair-$codeSuffix"

        if (Get-Command -Name $repairFunctionName -ErrorAction SilentlyContinue) {
            try {
                Write-Log -Level INFO -Message "Calling $repairFunctionName for error code $hexErr."
                & $repairFunctionName
                $Script:actionsTaken += "Invoked $repairFunctionName for error code $hexErr."
            }
            catch {
                Write-Log -Level ERROR -Message "$repairFunctionName threw an error: $($_.Exception.Message)"
            }
        }
        else {
            Write-Log -Level WARN -Message "No remediation function exists for error code $hexErr."
        }
    }
}

########## Reattempt Synchronisation ##########
if ($AutomaticallyRemediate -and $Script:updateErrors.Count -gt 0 -and -not $syncSucceeded) {
    Write-Log -Level DEBUG -Message "Starting sync attempt after remediations"
    $syncSucceeded = Invoke-SyncAttempt
    $syncs += 1
    Write-Log -Level DEBUG -Message "Sync $syncs finished. Success: $syncSucceeded"

    if ($syncSucceeded) {
        Write-Log -Level INFO -Message "Sync succeeded after remediation (attempt $syncs)."
    }
    else {
        Write-Log -Level ERROR -Message "Sync did not succeed after remediation (attempt $syncs)."
        Write-LogEvent -eventID 1016 -entryType Error -message "WSUS sync failed after $syncs attempt(s), including post-remediation retry."
    }
}

##################################################
# Report generation
##################################################

function Export-AuditCsv {
    <#
    .SYNOPSIS
        Writes the run summary, update errors, and actions taken to CSV files.
    #>
    if (-not (Test-Path $Script:reportFolder)) {
        New-Item -ItemType Directory -Path $Script:reportFolder -Force -ErrorAction Stop | Out-Null
    }

    $summaryPath = Join-Path $Script:reportFolder "$($Script:reportBaseName)_Summary.csv"
    $summary = [PSCustomObject]@{
        RunTime            = $Script:startTime
        WUServer           = $WUServer
        WUStatusServer     = $WUStatusServer
        CertificateTrusted = $certTrustResult.IsTrusted
        RebootPending      = $rebootPending
        RebootReasons      = ($rebootReasons -join '; ')
        FreeSpaceGB        = $freeSpaceGB
        TotalSpaceGB       = $totalSpaceGB
        SyncSucceeded      = $syncSucceeded
        SyncAttempts       = $syncs
        UpdateErrorCount   = $Script:updateErrors.Count
        ActionsTakenCount  = $Script:actionsTaken.Count
    }
    $summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
    Write-Log -Level INFO -Message "Wrote CSV: $summaryPath"

    $errorsPath = Join-Path $Script:reportFolder "$($Script:reportBaseName)_UpdateErrors.csv"
    if ($Script:updateErrors.Count -gt 0) {
        $Script:updateErrors | Export-Csv -Path $errorsPath -NoTypeInformation -Encoding UTF8
    }
    else {
        "No findings" | Out-File -FilePath $errorsPath -Encoding UTF8
    }
    Write-Log -Level INFO -Message "Wrote CSV: $errorsPath"

    $actionsPath = Join-Path $Script:reportFolder "$($Script:reportBaseName)_ActionsTaken.csv"
    if ($Script:actionsTaken.Count -gt 0) {
        $Script:actionsTaken | ForEach-Object { [PSCustomObject]@{ Action = $_ } } | Export-Csv -Path $actionsPath -NoTypeInformation -Encoding UTF8
    }
    else {
        "No findings" | Out-File -FilePath $actionsPath -Encoding UTF8
    }
    Write-Log -Level INFO -Message "Wrote CSV: $actionsPath"
}

function Build-HtmlKeyValueTable {
    <#
    .SYNOPSIS
        Builds an HTML key/value table from a hashtable, in insertion order.
    #>
    param(
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Data
    )
    $rows = foreach ($key in $Data.Keys) {
        "<tr><td><strong>$key</strong></td><td>$($Data[$key])</td></tr>"
    }
    return "<table>$($rows -join '')</table>"
}

function Build-HtmlDataTable {
    <#
    .SYNOPSIS
        Builds an HTML table from an array of PSCustomObjects, or a "no
        findings" message if the array is empty.
    #>
    param(
        [Parameter(Mandatory)][array]$Data,
        [string]$RowClass = "warn"
    )
    if ($Data.Count -eq 0) {
        return "<p class='ok'>No findings.</p>"
    }
    $headers = $Data[0].PSObject.Properties.Name
    $headerRow = ($headers | ForEach-Object { "<th>$_</th>" }) -join ""
    $rows = foreach ($item in $Data) {
        $cells = ($headers | ForEach-Object { "<td>$($item.$_)</td>" }) -join ""
        "<tr class='$RowClass'>$cells</tr>"
    }
    return "<table><tr>$headerRow</tr>$($rows -join '')</table>"
}

function Export-AuditHtml {
    <#
    .SYNOPSIS
        Builds and writes the full HTML report.
    #>
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

    $summaryClass = if (-not $syncSucceeded -or $Script:updateErrors.Count -gt 0) { "risk" } else { "ok" }
    $summary = @"
<div class='summary'>
<span>Sync succeeded: $syncSucceeded ($syncs attempt(s))</span>
<span>Update errors: $($Script:updateErrors.Count)</span>
<span>Reboot pending: $rebootPending</span>
<span>Certificate trusted: $($certTrustResult.IsTrusted)</span>
<span>Actions taken: $($Script:actionsTaken.Count)</span>
</div>
"@

    $configData = [ordered]@{
        "WSUS Server"          = $WUServer
        "WSUS Status Server"   = $WUStatusServer
        "GPO changed WUServer" = ($initialWUServer -ne $WUServer)
    }
    $connectivityData = [ordered]@{
        "Ping reachable"       = $pingCheck
        "Port reachable"       = $portCheck
        "Certificate trusted"  = $certTrustResult.IsTrusted
        "Certificate issuer"   = $certTrustResult.Issuer
        "Certificate expiry"   = $certTrustResult.NotAfter
    }
    $healthData = [ordered]@{
        "Reboot pending"  = $rebootPending
        "Reboot reasons"  = ($rebootReasons -join ', ')
        "Free space (GB)" = $freeSpaceGB
        "Total space (GB)" = $totalSpaceGB
    }
    $syncData = [ordered]@{
        "Sync succeeded" = $syncSucceeded
        "Sync attempts"  = $syncs
    }

    $body = ""
    $body += "<h2>Configuration</h2>" + (Build-HtmlKeyValueTable -Data $configData)
    $body += "<h2>Connectivity &amp; Certificate</h2>" + (Build-HtmlKeyValueTable -Data $connectivityData)
    $body += "<h2>System Health</h2>" + (Build-HtmlKeyValueTable -Data $healthData)
    $body += "<h2>Service States</h2>" + (Build-HtmlDataTable -Data $Script:serviceStates -RowClass "warn")
    $body += "<h2>Synchronisation</h2>" + (Build-HtmlKeyValueTable -Data $syncData)
    $body += "<h2>Update Errors ($($Script:updateErrors.Count))</h2>" + (Build-HtmlDataTable -Data $Script:updateErrors -RowClass "risk")
    $actionsForTable = $Script:actionsTaken | ForEach-Object { [PSCustomObject]@{ Action = $_ } }
    $body += "<h2>Actions Taken ($($Script:actionsTaken.Count))</h2>" + (Build-HtmlDataTable -Data $actionsForTable -RowClass "warn")

    $footnote = @"
<p class='footnote'>
Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") by WSUS-ClientSync.ps1 on $env:COMPUTERNAME.
</p>
"@

    $html = "<html><head><title>WSUS Client Sync Report</title>$style</head><body><h1>WSUS Client Sync Report - $env:COMPUTERNAME</h1>$summary$body$footnote</body></html>"

    $htmlPath = Join-Path $Script:reportFolder "$($Script:reportBaseName).html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log -Level INFO -Message "Wrote HTML report: $htmlPath"
}

Try {
    Export-AuditCsv
    Export-AuditHtml
}
Catch {
    Write-Log -Level ERROR -Message "Failed to write report: $($_.Exception.Message)"
}

Write-Log -Level INFO -Message "WSUS Client Sync script has completed"
Write-LogEvent -eventID 1001 -entryType Information -message "WSUS Client Sync script has completed"