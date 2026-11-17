#Requires -Version 5.1
<#
.SYNOPSIS
    Scans Entra ID app registrations for expiring or expired secrets and certificates.

.DESCRIPTION
    EntraAppExpiryScanner enumerates every app registration in a tenant using the
    Microsoft Graph REST API and reports on:

      * Client secrets and certificates that are expired or expiring soon
      * App registrations with no assigned owner
      * App registrations with no credentials at all

    Findings are banded by severity (Expired, Critical, Warning, Notice) using
    configurable thresholds, and written to a timestamped HTML report and CSV file.

    The tool is read-only by design. It never creates, changes or removes anything in
    the tenant. The only changes it makes are to its own output folder (new reports
    and logs, plus retention cleanup of old ones).

    Authentication:
      * Interactive (default): delegated sign-in with the Application.Read.All scope.
      * App-only: certificate thumbprint or client secret, for Scheduled Task use.
        The app registration needs the Application.Read.All APPLICATION permission
        with admin consent.

    Only the Microsoft.Graph.Authentication module is required. It is installed to the
    current user scope automatically if missing. The full Microsoft Graph SDK is not
    needed, as all calls use Invoke-MgGraphRequest.

.PARAMETER TenantId
    Tenant ID or primary domain. Required for app-only authentication, optional for
    interactive sign-in.

.PARAMETER ClientId
    Application (client) ID of the app registration used for app-only authentication.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in the current user or local machine store. Selects
    certificate-based app-only authentication.

.PARAMETER ClientSecretCredential
    PSCredential where the username is the client ID and the password is the client
    secret. Selects secret-based app-only authentication.

.PARAMETER CriticalDays
    Credentials expiring within this many days are reported as Critical. Default 7.

.PARAMETER WarningDays
    Credentials expiring within this many days are reported as Warning. Default 30.

.PARAMETER NoticeDays
    Credentials expiring within this many days are reported as Notice. Default 60.
    Credentials expiring after this are considered healthy and are not reported
    unless -IncludeHealthy is used.

.PARAMETER HideExpired
    Excludes credentials that have already expired from the report.

.PARAMETER IncludeHealthy
    Includes credentials that are outside the notice window in the report.

.PARAMETER LogPath
    Full path of the log file. Default C:\Pickering-Cloud\Logs\Entra\EntraAppExpiryScanner.log.
    The file is appended to across runs and is created read-only (writes use -Force).

.PARAMETER ReportPath
    Folder for HTML and CSV reports. Default C:\Pickering-Cloud\Reports\Entra\EntraAppExpiryScanner.

.PARAMETER LoggingLevel
    Minimum level written to the log: Debug (1), Verbose (2), Info (3), Warn (4),
    Error (5), Critical (6) or None (0). Accepts the name or the number. Default is
    Info, or Debug when -Debug is supplied. The script never prompts for this, so it
    is safe to run unattended. Assigning $loggingLevel before dot-sourcing is not
    required, use this parameter instead.

.PARAMETER RetentionDays
    Reports older than this many days are removed from the report folder. Default 30.
    Use 0 to disable cleanup. The log file is a single appended file and is not
    removed by this setting.

.PARAMETER NoModuleInstall
    Prevents automatic installation of Microsoft.Graph.Authentication. The script
    exits if the module is not already present.

.PARAMETER DisableUpdateCheck
    Skips the check for a newer version. No network request is made for this purpose.

.PARAMETER DisableTelemetry
    Stops anonymous usage telemetry being sent. The update check still runs unless
    -DisableUpdateCheck is also used. Telemetry can also be disabled for every tool by
    setting the environment variable PICKERINGCLOUD_NOTELEMETRY to 1.

.EXAMPLE
    .\EntraAppExpiryScanner.ps1

    Interactive sign-in, default thresholds (7 / 30 / 60 days).

.EXAMPLE
    .\EntraAppExpiryScanner.ps1 -TenantId contoso.onmicrosoft.com -ClientId 00000000-0000-0000-0000-000000000000 -CertificateThumbprint ABCDEF0123456789ABCDEF0123456789ABCDEF01

    Unattended run using certificate authentication, suitable for a Scheduled Task.

.EXAMPLE
    .\EntraAppExpiryScanner.ps1 -CriticalDays 14 -WarningDays 45 -NoticeDays 90 -HideExpired

    Custom severity bands, with already-expired credentials excluded.

.EXAMPLE
    .\EntraAppExpiryScanner.ps1 -Debug

    Interactive run with Debug level messages written to the console and log file.

.NOTES
    Name:        EntraAppExpiryScanner
    Version:     1.0.0
    Author:      Bradley Pickering
    Repository:  Pickering-Cloud/PowerShell_Toolkit

    Event log: entries are written to the Application log under the source
    EntraAppExpiryScanner (registered on first run, which needs an elevated session).
    Findings are not errors. Finding expiring or expired credentials is the purpose of
    the tool, so only a scan that fails to complete is logged as an Error.
      3000  Information  Scan started
      3001  Information  Completed, nothing at Warning severity or above
      3002  Warning      Completed, at least one credential at Warning severity
      3003  Warning      Completed, at least one Critical or Expired credential
      3010  Error        The scan could not be completed

    Exit codes:
      0  The scan completed, whatever it found
      1  The scan could not be completed (module, authentication or Graph failure)
    Findings are reported through the report, the log and the event IDs above, not
    through the exit code.

    Expiry data covers passwordCredentials (secrets) and keyCredentials (certificates)
    on the application object. Enterprise application SAML signing certificates live
    on service principals and are not covered by this version.

    Update check and telemetry: after the scan, the script reads a static version file
    from pickering.cloud and tells you if a newer version exists. It never downloads or
    installs anything. Unless disabled, it also sends anonymous usage data (tool, version,
    OS, PowerShell version, timezone, run mode). No tenant, user or host details are sent.
    See TELEMETRY.md in the repository root for the full list.

    Owner lookups use Graph $batch (20 per request). If an owner lookup fails for an
    app, its owner state is reported as Unknown rather than flagged as ownerless.
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'Interactive')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppOnlyCertificate')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppOnlySecret')]
    [string]$TenantId,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppOnlyCertificate')]
    [string]$ClientId,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppOnlyCertificate')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppOnlySecret')]
    [System.Management.Automation.PSCredential]$ClientSecretCredential,

    [ValidateRange(1, 3650)]
    [int]$CriticalDays = 7,

    [ValidateRange(1, 3650)]
    [int]$WarningDays = 30,

    [ValidateRange(1, 3650)]
    [int]$NoticeDays = 60,

    [switch]$HideExpired,

    [switch]$IncludeHealthy,

    [ValidateNotNullOrEmpty()]
    [string]$LogPath = 'C:\Pickering-Cloud\Logs\Entra\EntraAppExpiryScanner.log',

    [ValidateNotNullOrEmpty()]
    [string]$ReportPath = 'C:\Pickering-Cloud\Reports\Entra\EntraAppExpiryScanner',

    [ValidateScript({
            $v = ([string]$_).Trim().ToUpper()
            if ($v -in 'DEBUG', 'VERBOSE', 'INFO', 'WARN', 'ERROR', 'CRITICAL', 'NONE', '0', '1', '2', '3', '4', '5', '6') { $true }
            else { throw 'LoggingLevel must be Debug, Verbose, Info, Warn, Error, Critical, None or a number from 0 to 6.' }
        })]
    $LoggingLevel,

    [ValidateRange(0, 3650)]
    [int]$RetentionDays = 30,

    [switch]$NoModuleInstall,

    [switch]$DisableUpdateCheck,

    [switch]$DisableTelemetry
)

# ------------------------------------------------------------------------------
# Script-level state
# ------------------------------------------------------------------------------
$ScriptName = 'EntraAppExpiryScanner'
$ScriptVersion = '1.0.0'
$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$GraphBase = 'https://graph.microsoft.com/v1.0'
$MinimumModuleVersion = [version]'2.0.0'
$UpdateCheckUrl = 'https://pickering.cloud/tools/versions.json'
$TelemetryUrl = 'https://pickering.cloud/api/telemetry'
$NetworkUserAgent = 'PickeringCloud-Toolkit'

# Logging state. $logPath and $loggingLevel are the same variables as the -LogPath and
# -LoggingLevel parameters (PowerShell variable names are case-insensitive).
$Script:eventLogName = 'Application'
$Script:eventLogSource = 'EntraAppExpiryScanner'
$Script:eventLogReady = $false
$logLevelMap = @{
    'NONE'     = 0
    'DEBUG'    = 1
    'VERBOSE'  = 2
    'INFO'     = 3
    'WARN'     = 4
    'ERROR'    = 5
    'CRITICAL' = 6
}

########## Configure Logging ##########

# Log file config
try {
    if (-not (Test-Path -Path $logPath)) {
        $logFolder = Split-Path -Path $logPath -Parent

        if (-not (Test-Path -Path $logFolder)) {
            New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
        }

        New-Item -ItemType File -Path $logPath -Force | Out-Null
        Set-ItemProperty -Path $logPath -Name IsReadOnly -Value $true
    }
}
catch {
    Write-Host ('Unable to create the log file {0}: {1}' -f $logPath, $_.Exception.Message) -ForegroundColor Red
    exit 1
}

# Sets logging level for this session. No prompt is shown so the script is safe to run
# unattended (Scheduled Task). Use -LoggingLevel to change it, or -Debug for Debug.
if ($null -eq $loggingLevel) {
    if ($DebugPreference -ne 'SilentlyContinue') {
        $loggingLevel = 1
    }
    else {
        $loggingLevel = 3
    }
}
else {
    $response = ([string]$loggingLevel).ToUpper().Trim()

    if ($logLevelMap.ContainsKey($response)) {
        $loggingLevel = $logLevelMap[$response]
    }
    else {
        $loggingLevel = [int]$response
    }
}

# Writes to defined log file
function Write-LogFile {
    <#
    .SYNOPSIS
        Writes a message to the script's log file, subject to the configured logging level.
    .DESCRIPTION
        Appends a timestamped, level-tagged line to the log file at
        $Script:logPath. The message is only written if its level is at or
        above the session's configured $loggingLevel threshold (see
        $logLevelMap). The log file is created read-only to prevent accidental
        external editing/deletion; -Force is used here to bypass that
        attribute specifically for this function's own writes.
    .PARAMETER message
        The text to log.
    .PARAMETER level
        The severity of this log entry. Must be one of Debug, Verbose, Info,
        Warn, Error, or Critical. Compared against the session's configured
        logging level threshold to decide whether the message is written.
    .EXAMPLE
        Write-LogFile -level Info -message "Scan completed successfully."

        Writes an Info-level entry to the log file, provided the current
        logging level is Info or lower severity (Debug/Verbose/Info).
    .OUTPUTS
        None. Writes to the log file as a side effect.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$message,
        [Parameter(Mandatory)]
        [ValidateSet("Debug", "Verbose", "Info", "Warn", "Error", "Critical")]
        [string]$level
    )
    $logPath = $Script:logPath
    $level = $level.ToUpper()
    $levelValue = $logLevelMap[$level]
    if ($levelValue -ge $loggingLevel) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $line = "$timestamp | [$level] | $message"
        Add-Content -Path $logPath -Value $line -Force
    }
}

# Configures Event Viewer Source if it doesn't exist
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Script:eventLogSource)) {
        New-EventLog -LogName $Script:eventLogName -Source $Script:eventLogSource
    }
    $Script:eventLogReady = $true
}
catch {
    Write-LogFile -level Warn -message "Could not register event log source '$Script:eventLogSource': $($_.Exception.Message). Event log writes will fail until this is resolved (requires an elevated session)."
}

# Writes to Event Log
function Write-LogEvent {
    <#
    .SYNOPSIS
        Writes an entry to the Windows Application Event Log.
    .DESCRIPTION
        Wraps Write-EventLog, writing under the script's registered event
        source. Used for the subset of conditions worth surfacing to
        centralised monitoring, distinct from the full-fidelity file log
        written via Write-LogFile.
    .PARAMETER logSource
        The event source to write under. Defaults to $Script:eventLogSource.
    .PARAMETER logName
        The event log to write to (e.g. "Application"). Defaults to
        $Script:eventLogName.
    .PARAMETER message
        The text of the event.
    .PARAMETER eventID
        The event ID to log. See the tool README for the event ID map.
    .PARAMETER entryType
        The event's severity: Error, Warning, Information, SuccessAudit, or
        FailureAudit.
    .EXAMPLE
        Write-LogEvent -eventID 3010 -entryType Error -message "Entra app expiry scan failed."

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

# ------------------------------------------------------------------------------
# Logging wrappers
# Neither function is gated behind WhatIf/ShouldProcess: logging always runs.
# ------------------------------------------------------------------------------
function Write-Log {
    <#
    .SYNOPSIS
        Logs a message to the log file and echoes it to the console.
    .DESCRIPTION
        Calls Write-LogFile, then echoes the same message to the console if its
        level meets the session's logging threshold. -Success only changes the
        console colour. The entry is still logged at the level supplied.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [ValidateSet('Debug', 'Verbose', 'Info', 'Warn', 'Error', 'Critical')]
        [string]$Level = 'Info',

        [switch]$Success
    )

    try {
        Write-LogFile -level $Level -message $Message
    }
    catch {
        Write-Host ('[LOGGING FAILURE] {0}' -f $_.Exception.Message) -ForegroundColor Red
    }

    if ($logLevelMap[$Level.ToUpper()] -ge $loggingLevel) {
        $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level.ToUpper(), $Message

        if ($Success) { Write-Host $line -ForegroundColor Green }
        else {
            switch ($Level) {
                'Critical' { Write-Host $line -ForegroundColor Red }
                'Error' { Write-Host $line -ForegroundColor Red }
                'Warn' { Write-Host $line -ForegroundColor Yellow }
                'Debug' { Write-Host $line -ForegroundColor DarkGray }
                'Verbose' { Write-Host $line -ForegroundColor DarkGray }
                default { Write-Host $line }
            }
        }
    }
}

function Send-LogEvent {
    <#
    .SYNOPSIS
        Writes an Application event log entry if the event source is available.
    .DESCRIPTION
        Wraps Write-LogEvent so that a missing event source (non-elevated session
        or PowerShell 7) never stops the scan. Failures are logged as Warn.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [int]$EventId,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.EventLogEntryType]$EntryType
    )

    if (-not $Script:eventLogReady) {
        Write-LogFile -level Debug -message ('Event {0} not written, event log source unavailable.' -f $EventId)
        return
    }

    try {
        Write-LogEvent -eventID $EventId -entryType $EntryType -message $Message
    }
    catch {
        Write-LogFile -level Warn -message ('Event log write failed for event {0}: {1}' -f $EventId, $_.Exception.Message)
    }
}

Write-LogFile -level Verbose -message "Logging has been configured"
Write-LogFile -level Debug -message "logPath=$Script:logPath; eventLogSource=$Script:eventLogSource; eventLogName=$Script:eventLogName"
Write-LogFile -level Info -message "Script is running - logging level is $loggingLevel"

# ------------------------------------------------------------------------------
# Report folder and retention
# ------------------------------------------------------------------------------
function Initialize-OutputFolder {
    [CmdletBinding()]
    param()

    # Folder creation is deliberately not gated: reports need somewhere to go.
    if (-not (Test-Path -Path $ReportPath -PathType Container)) {
        New-Item -Path $ReportPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
}

function Remove-ExpiredOutput {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Folder,

        [Parameter(Mandatory = $true)]
        [int]$OlderThanDays
    )

    if ($OlderThanDays -le 0) {
        Write-Log 'Retention cleanup disabled (RetentionDays is 0).' -Level Debug
        return
    }

    $cutoff = (Get-Date).AddDays(-$OlderThanDays)
    $removed = 0

    foreach ($path in $Folder) {
        try {
            $oldFiles = Get-ChildItem -Path $path -File -ErrorAction Stop |
                Where-Object { $_.LastWriteTime -lt $cutoff -and $_.Extension -in '.csv', '.html' }

            foreach ($file in $oldFiles) {
                if ($PSCmdlet.ShouldProcess($file.FullName, 'Remove report past retention period')) {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    $removed++
                    Write-Log ('Removed old file: {0}' -f $file.FullName) -Level Debug
                }
            }
        }
        catch {
            Write-Log ('Retention cleanup failed in {0}: {1}' -f $path, $_.Exception.Message) -Level Warn
        }
    }

    Write-Log ('Retention cleanup complete. Reports removed: {0} (older than {1} days).' -f $removed, $OlderThanDays)
}

# ------------------------------------------------------------------------------
# Prerequisites and authentication
# ------------------------------------------------------------------------------
function Initialize-GraphModule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([bool])]
    param()

    $installed = Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' |
        Where-Object { $_.Version -ge $MinimumModuleVersion } |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1

    if (-not $installed) {
        if ($NoModuleInstall) {
            Write-Log ('Microsoft.Graph.Authentication {0}+ is not installed and -NoModuleInstall was specified.' -f $MinimumModuleVersion) -Level Error
            return $false
        }

        if ($PSCmdlet.ShouldProcess('Microsoft.Graph.Authentication', 'Install module (CurrentUser scope)')) {
            try {
                Write-Log 'Installing Microsoft.Graph.Authentication to the current user scope...'
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                Install-Module -Name 'Microsoft.Graph.Authentication' -MinimumVersion $MinimumModuleVersion -Scope CurrentUser -Force -AllowClobber -Confirm:$false -ErrorAction Stop
                Write-Log 'Module installed.' -Level Info -Success
            }
            catch {
                Write-Log ('Module installation failed: {0}' -f $_.Exception.Message) -Level Error
                return $false
            }
        }
        else {
            Write-Log 'Module installation skipped (WhatIf). Cannot continue without it.' -Level Warn
            return $false
        }
    }

    try {
        Import-Module -Name 'Microsoft.Graph.Authentication' -MinimumVersion $MinimumModuleVersion -ErrorAction Stop
        Write-Log ('Microsoft.Graph.Authentication {0} loaded.' -f (Get-Module -Name 'Microsoft.Graph.Authentication').Version) -Level Debug
        return $true
    }
    catch {
        Write-Log ('Failed to import Microsoft.Graph.Authentication: {0}' -f $_.Exception.Message) -Level Error
        return $false
    }
}

function Connect-GraphSession {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        switch ($script:AuthMode) {
            'AppOnlyCertificate' {
                Write-Log 'Authenticating with app-only certificate.'
                Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
            }
            'AppOnlySecret' {
                Write-Log 'Authenticating with app-only client secret.'
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential -NoWelcome -ErrorAction Stop
            }
            default {
                Write-Log 'Authenticating interactively (delegated, Application.Read.All).'
                if ([string]::IsNullOrWhiteSpace($TenantId)) {
                    Connect-MgGraph -Scopes 'Application.Read.All' -NoWelcome -ErrorAction Stop
                }
                else {
                    Connect-MgGraph -TenantId $TenantId -Scopes 'Application.Read.All' -NoWelcome -ErrorAction Stop
                }
            }
        }

        $context = Get-MgContext
        if (-not $context) {
            Write-Log 'Connect-MgGraph returned no context.' -Level Error
            return $false
        }

        Write-Log ('Connected. Tenant: {0}, Account/App: {1}, Auth type: {2}' -f $context.TenantId, $(if ($context.Account) { $context.Account } else { $context.ClientId }), $context.AuthType) -Level Info -Success
        return $true
    }
    catch {
        Write-Log ('Authentication failed: {0}' -f $_.Exception.Message) -Level Error
        return $false
    }
}

# ------------------------------------------------------------------------------
# Graph helpers
# ------------------------------------------------------------------------------
function Invoke-GraphPaged {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $results = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $next = $Uri
    $page = 0

    while ($next) {
        $page++
        Write-Log ('GET page {0}: {1}' -f $page, $next) -Level Debug
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop

        foreach ($item in @($response.value)) {
            $results.Add($item)
        }

        $next = $response.'@odata.nextLink'
    }

    return , $results.ToArray()
}

function Get-AppOwnerMap {
    <#
    .SYNOPSIS
        Returns a hashtable of application object ID to an array of owner labels.
        A value of $null means the owner lookup failed for that application.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Application
    )

    $map = @{}
    $batchSize = 20

    for ($i = 0; $i -lt $Application.Count; $i += $batchSize) {
        $chunk = $Application[$i..([Math]::Min($i + $batchSize, $Application.Count) - 1)]

        $requests = foreach ($app in $chunk) {
            @{
                id     = [string]$app.id
                method = 'GET'
                url    = ('/applications/{0}/owners?$select=id,displayName,userPrincipalName' -f $app.id)
            }
        }

        $body = @{ requests = @($requests) } | ConvertTo-Json -Depth 5

        try {
            $batchResponse = Invoke-MgGraphRequest -Method POST -Uri ('{0}/$batch' -f $GraphBase) -Body $body -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop

            foreach ($item in @($batchResponse.responses)) {
                if ([int]$item.status -eq 200) {
                    $owners = @($item.body.value) | ForEach-Object {
                        if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName }
                    }
                    $map[[string]$item.id] = @($owners)
                }
                else {
                    Write-Log ('Owner lookup returned HTTP {0} for application {1}.' -f $item.status, $item.id) -Level Debug
                    $map[[string]$item.id] = $null
                }
            }
        }
        catch {
            Write-Log ('Owner batch {0} failed: {1}' -f ([Math]::Floor($i / $batchSize) + 1), $_.Exception.Message) -Level Warn
            foreach ($app in $chunk) {
                $map[[string]$app.id] = $null
            }
        }

        if (($i % 200) -eq 0 -and $i -gt 0) {
            Write-Log ('Owner lookups: {0} of {1} applications processed.' -f $i, $Application.Count) -Level Debug
        }
    }

    return $map
}

# ------------------------------------------------------------------------------
# Analysis helpers
# ------------------------------------------------------------------------------
function ConvertTo-UtcDate {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime()
    }

    return ([DateTimeOffset]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture)).UtcDateTime
}

function Get-ExpiryStatus {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$DaysRemaining
    )

    if ($DaysRemaining -lt 0) { return 'Expired' }
    if ($DaysRemaining -le $CriticalDays) { return 'Critical' }
    if ($DaysRemaining -le $WarningDays) { return 'Warning' }
    if ($DaysRemaining -le $NoticeDays) { return 'Notice' }
    return 'Healthy'
}

function New-CredentialFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)] $App,
        [Parameter(Mandatory = $true)] [string]$KeyKind,
        [Parameter(Mandatory = $true)] $KeyEntry,
        [Parameter(Mandatory = $true)] [string]$OwnerText,
        [Parameter(Mandatory = $true)] [datetime]$Now
    )

    $end = ConvertTo-UtcDate -Value $KeyEntry.endDateTime
    $start = ConvertTo-UtcDate -Value $KeyEntry.startDateTime

    if ($null -eq $end) {
        return $null
    }

    $days = [int][Math]::Floor(($end - $Now).TotalDays)

    [pscustomobject]@{
        FindingType     = 'Credential'
        Status          = Get-ExpiryStatus -DaysRemaining $days
        ApplicationName = [string]$App.displayName
        ApplicationId   = [string]$App.appId
        ObjectId        = [string]$App.id
        CredentialType  = $KeyKind
        CredentialName  = if ($KeyEntry.displayName) { [string]$KeyEntry.displayName } else { '(unnamed)' }
        KeyId           = [string]$KeyEntry.keyId
        StartDate       = if ($start) { $start.ToString('yyyy-MM-dd') } else { '' }
        ExpiryDate      = $end.ToString('yyyy-MM-dd')
        DaysRemaining   = $days
        Owners          = $OwnerText
    }
}

# ------------------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------------------
function ConvertTo-HtmlSafe {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()]
        $Text
    )

    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function New-HtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)] [object[]]$ExpiryFinding,
        [Parameter(Mandatory = $true)] [object[]]$NoOwnerFinding,
        [Parameter(Mandatory = $true)] [object[]]$NoKeyFinding,
        [Parameter(Mandatory = $true)] [object[]]$UnknownOwnerFinding,
        [Parameter(Mandatory = $true)] [int]$TotalApplications,
        [Parameter(Mandatory = $true)] [string]$TenantLabel
    )

    $sb = New-Object -TypeName System.Text.StringBuilder
    $generated = Get-Date -Format 'dd MMMM yyyy HH:mm'

    $counts = @{}
    foreach ($s in 'Expired', 'Critical', 'Warning', 'Notice', 'Healthy') {
        $counts[$s] = @($ExpiryFinding | Where-Object { $_.Status -eq $s }).Count
    }

    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en-GB"><head><meta charset="utf-8">')
    [void]$sb.AppendLine(('<title>{0} report</title>' -f $ScriptName))
    [void]$sb.AppendLine(@'
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2933;background:#f5f7fa}
h1{margin:0 0 4px 0;font-size:22px} h2{margin-top:32px;font-size:17px;border-bottom:2px solid #d9e2ec;padding-bottom:4px}
.meta{color:#52606d;font-size:13px;margin-bottom:16px}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}
.tile{background:#fff;border:1px solid #d9e2ec;border-left-width:6px;border-radius:4px;padding:10px 16px;min-width:110px}
.tile .n{font-size:24px;font-weight:600} .tile .l{font-size:12px;color:#52606d;text-transform:uppercase}
.t-Expired{border-left-color:#7b1e1e}.t-Critical{border-left-color:#d64545}.t-Warning{border-left-color:#f0a30a}
.t-Notice{border-left-color:#3b82c4}.t-Healthy{border-left-color:#3f9142}.t-Info{border-left-color:#829ab1}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
th{background:#243b53;color:#fff;text-align:left;padding:6px 8px;position:sticky;top:0}
td{padding:6px 8px;border-bottom:1px solid #e4e7eb;vertical-align:top}
tr:hover td{background:#f0f4f8}
.s{font-weight:600;padding:2px 8px;border-radius:10px;color:#fff;font-size:12px}
.s-Expired{background:#7b1e1e}.s-Critical{background:#d64545}.s-Warning{background:#f0a30a;color:#1f2933}
.s-Notice{background:#3b82c4}.s-Healthy{background:#3f9142}
.empty{color:#52606d;font-style:italic;padding:8px 0}
</style></head><body>
'@)

    [void]$sb.AppendLine(('<h1>Entra app registration expiry report</h1>'))
    [void]$sb.AppendLine(('<div class="meta">Tenant: {0} | Generated: {1} | {2} v{3} | Bands: Critical {4}d, Warning {5}d, Notice {6}d</div>' -f (ConvertTo-HtmlSafe $TenantLabel), $generated, $ScriptName, $ScriptVersion, $CriticalDays, $WarningDays, $NoticeDays))

    [void]$sb.AppendLine('<div class="tiles">')
    [void]$sb.AppendLine(('<div class="tile t-Info"><div class="n">{0}</div><div class="l">Apps scanned</div></div>' -f $TotalApplications))
    foreach ($s in 'Expired', 'Critical', 'Warning', 'Notice') {
        [void]$sb.AppendLine(('<div class="tile t-{0}"><div class="n">{1}</div><div class="l">{0}</div></div>' -f $s, $counts[$s]))
    }
    if ($IncludeHealthy) {
        [void]$sb.AppendLine(('<div class="tile t-Healthy"><div class="n">{0}</div><div class="l">Healthy</div></div>' -f $counts['Healthy']))
    }
    [void]$sb.AppendLine(('<div class="tile t-Info"><div class="n">{0}</div><div class="l">No owner</div></div>' -f $NoOwnerFinding.Count))
    [void]$sb.AppendLine(('<div class="tile t-Info"><div class="n">{0}</div><div class="l">No credentials</div></div>' -f $NoKeyFinding.Count))
    [void]$sb.AppendLine('</div>')

    # Credentials table
    [void]$sb.AppendLine('<h2>Credential expiry</h2>')
    if ($ExpiryFinding.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">No credentials matched the selected thresholds.</div>')
    }
    else {
        [void]$sb.AppendLine('<table><tr><th>Status</th><th>Application</th><th>App ID</th><th>Type</th><th>Credential name</th><th>Expiry</th><th>Days</th><th>Owners</th></tr>')
        foreach ($f in $ExpiryFinding) {
            [void]$sb.AppendLine(('<tr><td><span class="s s-{0}">{0}</span></td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td></tr>' -f
                $f.Status, (ConvertTo-HtmlSafe $f.ApplicationName), (ConvertTo-HtmlSafe $f.ApplicationId), $f.CredentialType,
                (ConvertTo-HtmlSafe $f.CredentialName), $f.ExpiryDate, $f.DaysRemaining, (ConvertTo-HtmlSafe $f.Owners)))
        }
        [void]$sb.AppendLine('</table>')
    }

    # No owner
    [void]$sb.AppendLine('<h2>App registrations with no owner</h2>')
    if ($NoOwnerFinding.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">None found.</div>')
    }
    else {
        [void]$sb.AppendLine('<table><tr><th>Application</th><th>App ID</th><th>Object ID</th></tr>')
        foreach ($f in $NoOwnerFinding) {
            [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-HtmlSafe $f.ApplicationName), (ConvertTo-HtmlSafe $f.ApplicationId), (ConvertTo-HtmlSafe $f.ObjectId)))
        }
        [void]$sb.AppendLine('</table>')
    }

    # No credentials
    [void]$sb.AppendLine('<h2>App registrations with no credentials</h2>')
    if ($NoKeyFinding.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">None found.</div>')
    }
    else {
        [void]$sb.AppendLine('<table><tr><th>Application</th><th>App ID</th><th>Object ID</th><th>Owners</th></tr>')
        foreach ($f in $NoKeyFinding) {
            [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (ConvertTo-HtmlSafe $f.ApplicationName), (ConvertTo-HtmlSafe $f.ApplicationId), (ConvertTo-HtmlSafe $f.ObjectId), (ConvertTo-HtmlSafe $f.Owners)))
        }
        [void]$sb.AppendLine('</table>')
    }

    if ($UnknownOwnerFinding.Count -gt 0) {
        [void]$sb.AppendLine(('<h2>Owner lookup failed</h2><div class="empty">{0} application(s) could not have their owners checked and are not included in the no-owner list. See the log for details.</div>' -f $UnknownOwnerFinding.Count))
    }

    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}

# ------------------------------------------------------------------------------
# Update check and telemetry
# Both run after the scan, are optional, and can never affect its result. Every
# failure is logged at Debug and ignored. Nothing is downloaded or installed.
# ------------------------------------------------------------------------------
function Get-LatestToolVersion {
    <#
    .SYNOPSIS
        Reads the latest published version of this tool from the static version file.
    .DESCRIPTION
        Makes a plain GET request with a generic User-Agent and sends no data. Returns
        $null if the check fails for any reason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $response = Invoke-RestMethod -Uri $UpdateCheckUrl -Method Get -TimeoutSec 5 -UserAgent $NetworkUserAgent -ErrorAction Stop
        $entry = $response.tools.$ScriptName

        if (-not $entry) {
            Write-Log ('Update check: {0} is not listed in the version file.' -f $ScriptName) -Level Debug
            return $null
        }

        $latest = [version](([string]$entry.version -split '-')[0])
        $current = [version](($ScriptVersion -split '-')[0])

        return [pscustomobject]@{
            Version  = [string]$entry.version
            Released = [string]$entry.released
            Url      = [string]$entry.url
            Newer    = ($latest -gt $current)
        }
    }
    catch {
        Write-Log ('Update check failed: {0}' -f $_.Exception.Message) -Level Debug
        return $null
    }
}

function Show-UpdateNotice {
    <#
    .SYNOPSIS
        Tells the user a newer version exists and, in an interactive session only, offers to open the release page.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Latest
    )

    Write-Log ('Update available: {0} {1} (you have {2}). Release page: {3}' -f $ScriptName, $Latest.Version, $ScriptVersion, $Latest.Url)

    # Never prompt in unattended runs or dry runs.
    if ($script:RunMode -ne 'interactive' -or $WhatIfPreference) {
        return
    }

    $answer = Read-Host 'Open the release page in your browser now? (y/N)'
    if ($answer.Trim().ToLower() -in 'y', 'yes') {
        # Only open GitHub links, in case the version file were ever tampered with.
        if ($Latest.Url -match '^https://github\.com/') {
            Start-Process -FilePath $Latest.Url
        }
        else {
            Write-Log ('Not opening {0}: it is not a github.com address.' -f $Latest.Url) -Level Warn
        }
    }
}

function Send-ToolTelemetry {
    <#
    .SYNOPSIS
        Sends anonymous usage telemetry.
    .DESCRIPTION
        Sends tool name, tool version, OS caption and build, PowerShell version and
        edition, timezone ID and run mode. The server adds the country from the request
        and a daily salted hash of the IP address. No tenant, user, host or application
        data is ever included. See TELEMETRY.md in the repository root.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    function Limit-Text {
        param([string]$Text, [int]$Max)
        $clean = ($Text -replace '[\x00-\x1F\x7F]', '').Trim()
        if ($clean.Length -gt $Max) { $clean = $clean.Substring(0, $Max) }
        return $clean
    }

    try {
        try {
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $osCaption = [string]$osInfo.Caption
            $osBuild = [string]$osInfo.BuildNumber
        }
        catch {
            $osCaption = [Environment]::OSVersion.VersionString
            $osBuild = [string][Environment]::OSVersion.Version.Build
        }

        $payload = [ordered]@{
            tool      = $ScriptName
            version   = $ScriptVersion
            os        = Limit-Text -Text $osCaption -Max 64
            osBuild   = Limit-Text -Text $osBuild -Max 32
            psVersion = Limit-Text -Text $PSVersionTable.PSVersion.ToString() -Max 32
            psEdition = if ($PSVersionTable.PSEdition -eq 'Core') { 'Core' } else { 'Desktop' }
            timezone  = Limit-Text -Text ([TimeZoneInfo]::Local.Id) -Max 64
            runMode   = $script:RunMode
        }

        $json = $payload | ConvertTo-Json -Compress
        Write-Log ('Telemetry payload: {0}' -f $json) -Level Debug

        if ($PSCmdlet.ShouldProcess($TelemetryUrl, 'Send anonymous usage telemetry')) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $bytes = [Text.Encoding]::UTF8.GetBytes($json)
            Invoke-RestMethod -Uri $TelemetryUrl -Method Post -Body $bytes -ContentType 'application/json' -TimeoutSec 5 -UserAgent $NetworkUserAgent -ErrorAction Stop | Out-Null
            Write-Log 'Telemetry sent.' -Level Debug
        }
    }
    catch {
        Write-Log ('Telemetry not sent: {0}' -f $_.Exception.Message) -Level Debug
    }
}

function Invoke-UpdateCheckAndTelemetry {
    [CmdletBinding()]
    param()

    if ($DisableUpdateCheck) {
        Write-Log 'Update check disabled.' -Level Debug
    }
    else {
        $latest = Get-LatestToolVersion
        if ($latest -and $latest.Newer) {
            Show-UpdateNotice -Latest $latest
        }
        elseif ($latest) {
            Write-Log ('Update check: {0} {1} is the latest version.' -f $ScriptName, $ScriptVersion) -Level Debug
        }
    }

    $telemetryOff = $DisableTelemetry -or ($env:PICKERINGCLOUD_NOTELEMETRY -in '1', 'true')
    if ($telemetryOff) {
        Write-Log 'Telemetry disabled.' -Level Debug
    }
    else {
        Write-Log 'Anonymous usage telemetry is on. Disable it with -DisableTelemetry or PICKERINGCLOUD_NOTELEMETRY=1. See TELEMETRY.md in the repository root.'
        Send-ToolTelemetry
    }
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
$exitCode = 0
$script:AuthMode = $PSCmdlet.ParameterSetName

# Run mode is used by the update notice (never prompt unattended) and by telemetry.
$script:RunMode = 'interactive'
if ($script:AuthMode -ne 'Interactive') {
    $script:RunMode = 'unattended'
}
elseif (-not [Environment]::UserInteractive -or @([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-NonI' }).Count -gt 0) {
    $script:RunMode = 'unattended'
}

try {
    Initialize-OutputFolder
}
catch {
    Write-Log ('Unable to create the report folder {0}: {1}' -f $ReportPath, $_.Exception.Message) -Level Error
    Send-LogEvent -EventId 3010 -EntryType Error -Message ('{0}: unable to create the report folder {1}.' -f $ScriptName, $ReportPath)
    exit 1
}

Write-Log ('{0} v{1} starting.' -f $ScriptName, $ScriptVersion)
Send-LogEvent -EventId 3000 -EntryType Information -Message ('{0} v{1} started. Auth mode: {2}.' -f $ScriptName, $ScriptVersion, $script:AuthMode)
Write-Log ('Auth mode: {0}. Bands: Critical {1}d, Warning {2}d, Notice {3}d. HideExpired: {4}. IncludeHealthy: {5}.' -f $script:AuthMode, $CriticalDays, $WarningDays, $NoticeDays, $HideExpired.IsPresent, $IncludeHealthy.IsPresent)

if (-not ($CriticalDays -lt $WarningDays -and $WarningDays -lt $NoticeDays)) {
    Write-Log 'Thresholds must satisfy CriticalDays < WarningDays < NoticeDays.' -Level Error
    Send-LogEvent -EventId 3010 -EntryType Error -Message ('{0}: invalid thresholds, CriticalDays must be less than WarningDays, which must be less than NoticeDays.' -f $ScriptName)
    exit 1
}

try {
    Remove-ExpiredOutput -Folder @($ReportPath) -OlderThanDays $RetentionDays

    if (-not (Initialize-GraphModule)) {
        Send-LogEvent -EventId 3010 -EntryType Error -Message ('{0}: the Microsoft.Graph.Authentication module is unavailable. See the log for details.' -f $ScriptName)
        $exitCode = 1
        exit 1
    }

    if (-not (Connect-GraphSession)) {
        Send-LogEvent -EventId 3010 -EntryType Error -Message ('{0}: authentication to Microsoft Graph failed. See the log for details.' -f $ScriptName)
        $exitCode = 1
        exit 1
    }

    $tenantLabel = (Get-MgContext).TenantId

    # Retrieve applications
    Write-Log 'Retrieving app registrations...'
    $selectFields = 'id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials'
    $applications = Invoke-GraphPaged -Uri ('{0}/applications?$select={1}&$top=999' -f $GraphBase, $selectFields)
    Write-Log ('Retrieved {0} app registrations.' -f $applications.Count) -Level Info -Success

    # Retrieve owners
    Write-Log 'Retrieving owners (Graph batch)...'
    $ownerMap = Get-AppOwnerMap -Application $applications
    $failedOwnerLookups = @($ownerMap.Values | Where-Object { $null -eq $_ }).Count
    if ($failedOwnerLookups -gt 0) {
        Write-Log ('Owner lookup failed for {0} application(s). They will be reported as Unknown.' -f $failedOwnerLookups) -Level Warn
    }

    # Analyse
    Write-Log 'Analysing credentials...'
    $now = (Get-Date).ToUniversalTime()
    $credentialFindings = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $noOwnerFindings = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $noCredentialFindings = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $unknownOwnerFindings = New-Object -TypeName 'System.Collections.Generic.List[object]'

    foreach ($app in $applications) {
        $ownerList = $ownerMap[[string]$app.id]
        $ownerKnown = ($null -ne $ownerList)

        if ($ownerKnown) {
            $ownerText = if (@($ownerList).Count -gt 0) { (@($ownerList) -join '; ') } else { '(none)' }
        }
        else {
            $ownerText = '(unknown)'
            $unknownOwnerFindings.Add($app)
        }

        $secrets = @($app.passwordCredentials)
        $certs = @($app.keyCredentials)

        foreach ($secret in $secrets) {
            $finding = New-CredentialFinding -App $app -KeyKind 'Secret' -KeyEntry $secret -OwnerText $ownerText -Now $now
            if ($finding) { $credentialFindings.Add($finding) }
        }

        foreach ($cert in $certs) {
            $finding = New-CredentialFinding -App $app -KeyKind 'Certificate' -KeyEntry $cert -OwnerText $ownerText -Now $now
            if ($finding) { $credentialFindings.Add($finding) }
        }

        if ($secrets.Count -eq 0 -and $certs.Count -eq 0) {
            $noCredentialFindings.Add([pscustomobject]@{
                    FindingType     = 'NoCredentials'
                    Status          = 'Info'
                    ApplicationName = [string]$app.displayName
                    ApplicationId   = [string]$app.appId
                    ObjectId        = [string]$app.id
                    CredentialType  = ''
                    CredentialName  = ''
                    KeyId           = ''
                    StartDate       = ''
                    ExpiryDate      = ''
                    DaysRemaining   = $null
                    Owners          = $ownerText
                })
        }

        if ($ownerKnown -and @($ownerList).Count -eq 0) {
            $noOwnerFindings.Add([pscustomobject]@{
                    FindingType     = 'NoOwner'
                    Status          = 'Info'
                    ApplicationName = [string]$app.displayName
                    ApplicationId   = [string]$app.appId
                    ObjectId        = [string]$app.id
                    CredentialType  = ''
                    CredentialName  = ''
                    KeyId           = ''
                    StartDate       = ''
                    ExpiryDate      = ''
                    DaysRemaining   = $null
                    Owners          = '(none)'
                })
        }
    }

    # Apply report filters
    $reportCredentials = @($credentialFindings | Where-Object {
            if ($_.Status -eq 'Healthy' -and -not $IncludeHealthy) { return $false }
            if ($_.Status -eq 'Expired' -and $HideExpired) { return $false }
            return $true
        } | Sort-Object -Property DaysRemaining, ApplicationName)

    $statusCounts = @{}
    foreach ($s in 'Expired', 'Critical', 'Warning', 'Notice', 'Healthy') {
        $statusCounts[$s] = @($credentialFindings | Where-Object { $_.Status -eq $s }).Count
    }

    Write-Log ('Credentials found: {0}. Expired {1}, Critical {2}, Warning {3}, Notice {4}, Healthy {5}.' -f $credentialFindings.Count, $statusCounts['Expired'], $statusCounts['Critical'], $statusCounts['Warning'], $statusCounts['Notice'], $statusCounts['Healthy'])
    Write-Log ('Apps with no owner: {0}. Apps with no credentials: {1}.' -f $noOwnerFindings.Count, $noCredentialFindings.Count)

    # Write reports
    $htmlPath = Join-Path -Path $ReportPath -ChildPath ('EntraAppExpiryScanner_{0}.html' -f $RunStamp)
    $csvPath = Join-Path -Path $ReportPath -ChildPath ('EntraAppExpiryScanner_{0}.csv' -f $RunStamp)

    $html = New-HtmlReport -ExpiryFinding $reportCredentials -NoOwnerFinding @($noOwnerFindings) -NoKeyFinding @($noCredentialFindings) -UnknownOwnerFinding @($unknownOwnerFindings) -TotalApplications $applications.Count -TenantLabel $tenantLabel
    Set-Content -Path $htmlPath -Value $html -Encoding UTF8 -ErrorAction Stop
    Write-Log ('HTML report written: {0}' -f $htmlPath) -Level Info -Success

    $csvRows = @($reportCredentials) + @($noOwnerFindings) + @($noCredentialFindings)
    if ($csvRows.Count -gt 0) {
        $csvRows | Select-Object FindingType, Status, ApplicationName, ApplicationId, ObjectId, CredentialType, CredentialName, KeyId, StartDate, ExpiryDate, DaysRemaining, Owners |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Log ('CSV report written: {0}' -f $csvPath) -Level Info -Success
    }
    else {
        Write-Log 'No findings to export, CSV not created.'
    }

    # Exit code
    if ($statusCounts['Expired'] -gt 0 -or $statusCounts['Critical'] -gt 0) {
        Write-Log 'Result: one or more credentials are Expired or Critical.' -Level Warn
        Send-LogEvent -EventId 3003 -EntryType Warning -Message ('{0}: {1} expired and {2} critical credential(s) found. Report: {3}' -f $ScriptName, $statusCounts['Expired'], $statusCounts['Critical'], $htmlPath)
    }
    elseif ($statusCounts['Warning'] -gt 0) {
        Write-Log 'Result: one or more credentials are at Warning severity.' -Level Warn
        Send-LogEvent -EventId 3002 -EntryType Warning -Message ('{0}: {1} credential(s) at Warning severity. Report: {2}' -f $ScriptName, $statusCounts['Warning'], $htmlPath)
    }
    else {
        Write-Log 'Result: no credentials at Warning severity or above.' -Level Info -Success
        Send-LogEvent -EventId 3001 -EntryType Information -Message ('{0}: no credentials at Warning severity or above. Report: {1}' -f $ScriptName, $htmlPath)
    }
}
catch {
    Write-Log ('Scan failed: {0}' -f $_.Exception.Message) -Level Error
    Write-Log ('Location: {0}' -f $_.InvocationInfo.PositionMessage) -Level Debug
    Send-LogEvent -EventId 3010 -EntryType Error -Message ('{0}: scan failed. {1}' -f $ScriptName, $_.Exception.Message)
    $exitCode = 1
}
finally {
    try {
        if (Get-Command -Name Disconnect-MgGraph -ErrorAction SilentlyContinue) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
    catch {
        Write-Log ('Disconnect warning: {0}' -f $_.Exception.Message) -Level Debug
    }
    try {
        Invoke-UpdateCheckAndTelemetry
    }
    catch {
        Write-Log ('Update check or telemetry error: {0}' -f $_.Exception.Message) -Level Debug
    }
    Write-Log ('{0} finished with exit code {1}.' -f $ScriptName, $exitCode)
}

exit $exitCode