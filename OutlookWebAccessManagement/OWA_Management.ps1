<#
    .SYNOPSIS
        Script to block Outlook Web Access for users with a F1 license

    .DESCRIPTION
        Checks against configured Entra environment to retrieve license(s) and will disable OWA where required to avoid invalidating license

    .PARAMETER Setup
        Runs interactive service principal creation if one is not already configured. Requires Application Administrator (or Global Administrator) and Privileged Role Administrator rights in Entra. Not needed on normal unattended runs once the service principal exists.

    .PARAMETER LogPath
        Log file location. Defaults to C:\ProgramData\PickeringCloud\OutlookWebAccessManagement\Logs\OutlookWebAccessManagement.log. The file is appended to across runs and rotated at 10 MB.

    .PARAMETER LoggingLevel
        Debug, Verbose, Info, Warn, Error, Critical or None (1 to 7, 0 also means None). Defaults to Info. -Debug and -Verbose raise it if this is not set.

    .PARAMETER ReportPath
        Folder for the daily audit CSV and the BlockedUsers.psd1 state file. Defaults to C:\ProgramData\PickeringCloud\OutlookWebAccessManagement\Reports.

    .PARAMETER RetentionDays
        Daily audit CSVs older than this are removed. Defaults to 0 (keep them all), because the CSVs are the audit trail. The state file is never removed.

    .PARAMETER DisableUpdateCheck
        Skips the check for a newer version. No network request is made for this purpose.

    .PARAMETER DisableTelemetry
        Stops anonymous usage telemetry being sent. The update check still runs unless -DisableUpdateCheck is also used. Telemetry can also be disabled for every tool at once by setting the environment variable PICKERINGCLOUD_NOTELEMETRY (or DO_NOT_TRACK) to 1, for example via Group Policy.

    .EXAMPLE
        .\Manage-OWA.ps1

        Runs the script normally: connects using the existing service principal, queries the tenant for F1-licensed users and mailboxes without a qualifying licence, blocks/unblocks Outlook client access accordingly, and updates the report and state files.

    .EXAMPLE
        .\Manage-OWA.ps1 -Setup

        Runs interactive service principal setup first (if not already configured), then continues into a normal run.

    .OUTPUTS
        None. Writes progress to the console and to the log file (see -LogPath), appends blocked/unblocked actions to a daily CSV report named OutlookWebAccessManagement_yyyyMMdd.csv in -ReportPath, and maintains a persistent state file (BlockedUsers.psd1) in the same folder tracking currently blocked users. On first run after upgrading from 1.1.0, an existing state file at C:\Pickering-Cloud\Reports\OWAManagement\BlockedUsers.psd1 is copied to the new location.

    .NOTES
        Author: Bradley Pickering
        Version: 1.2.0
        Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Applications, ExchangeOnlineManagement modules.
        Requires: Exchange Administrator directory role assigned to the service principal, and admin consent granted on its Graph application permissions, before the first unattended run.
        Update check and telemetry: after the run, the script reads a static version file from pickering.cloud and tells you if a newer version exists. It never downloads or installs anything. Unless disabled, it also sends anonymous usage data (tool, version, OS, PowerShell version, timezone, run mode). No tenant, user, mailbox or licence details are sent. See TELEMETRY.md in the repository root for the full list.
#>

##################################################
# Script Parameters
##################################################
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # ---- Script-specific parameters go here (each one ends with a comma) ----
    [switch]$Setup,

    # ---- Standard toolkit parameters (do not remove) ----
    [string]$LogPath,
    [string]$LoggingLevel,
    [string]$ReportPath,
    [ValidateRange(0, 3650)]
    [int]$RetentionDays,
    [switch]$DisableUpdateCheck,
    [switch]$DisableTelemetry
)

#region PC-CONFIG

# Per-tool values
$ScriptName    = 'OutlookWebAccessManagement'
$ScriptVersion = '1.2.0'

# Toolkit-wide values
$UpdateCheckUrl        = 'https://pickering.cloud/tools/versions.json'
$TelemetryUrl          = 'https://pickering.cloud/api/telemetry'
$NetworkUserAgent      = 'PickeringCloud-Toolkit'
$UpdateUrlAllowPattern = '^https://github\.com/'
$TelemetryOptOutEnvVar = 'PICKERINGCLOUD_NOTELEMETRY'
$TelemetryDocName      = 'TELEMETRY.md'
$VendorFolderName      = 'PickeringCloud'

# Defaults used when the matching parameter is not supplied
$DefaultLoggingLevel  = 'Info'
$DefaultRetentionDays = 0    # (tool override) The daily CSVs are the audit trail, so keep them unless -RetentionDays is set.
$DefaultDataRoot      = Join-Path -Path ([Environment]::GetFolderPath('CommonApplicationData')) -ChildPath ('{0}\{1}' -f $VendorFolderName, $ScriptName)
$DefaultLogPath       = Join-Path -Path $DefaultDataRoot -ChildPath ('Logs\{0}.log' -f $ScriptName)
$DefaultReportPath    = Join-Path -Path $DefaultDataRoot -ChildPath 'Reports'

# Log file behaviour
$LogMaxSizeMB      = 10      # Rotate at this size. 0 disables rotation.
$LogArchivesToKeep = 5       # Rotated copies kept (Name.1.log is the newest).
$RedactLogSecrets  = $true   # Best-effort masking of passwords, secrets and tokens.

# Windows event log
$EventLogName   = 'Application'
$EventLogSource = $ScriptName
#endregion PC-CONFIG

#region PC-TEMPLATE v1.1.1
$TemplateVersion = '1.1.1'

# NONE sits above Critical so that a threshold of NONE suppresses every message.
$logLevelMap = @{
    'DEBUG'    = 1
    'VERBOSE'  = 2
    'INFO'     = 3
    'WARN'     = 4
    'ERROR'    = 5
    'CRITICAL' = 6
    'NONE'     = 7
}

# ------------------------------------------------------------------------------
# Text helpers
# ------------------------------------------------------------------------------
function Limit-Text {
    <#
    .SYNOPSIS
        Strips control characters and trims text to a maximum length.
    .DESCRIPTION
        Used for anything that comes from outside the script (remote files, system
        values) before it is logged or sent.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Text,
        [int]$Max = 256
    )

    $clean = ($Text -replace '[\x00-\x1F\x7F]', '').Trim()
    if ($clean.Length -gt $Max) { $clean = $clean.Substring(0, $Max) }
    return $clean
}

function Protect-LogText {
    <#
    .SYNOPSIS
        Masks common secret patterns in text before it is logged.
    .DESCRIPTION
        Best effort only. It catches "Bearer <token>" and key=value or key: value pairs
        where the key looks like a password, secret, token or API key. It does not replace
        simply never logging secrets.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Text)

    if (-not $RedactLogSecrets -or [string]::IsNullOrEmpty($Text)) { return $Text }

    $masked = $Text -replace '(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*', 'Bearer ***'
    $masked = $masked -replace '(?i)\b(password|passwd|pwd|secret|client_?secret|token|access_?token|api[_-]?key)\b(["'']?\s*[=:]\s*)("[^"]*"|''[^'']*''|\S+)', '$1$2***'
    return $masked
}

# ------------------------------------------------------------------------------
# Configuration checks and run mode
# ------------------------------------------------------------------------------
function Test-ToolConfig {
    <#
    .SYNOPSIS
        Checks the CONFIG block and returns a list of problems (empty if all is well).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $problems = New-Object -TypeName 'System.Collections.Generic.List[string]'

    if ($ScriptName -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') {
        $problems.Add('ScriptName must be 1 to 64 characters: letters, digits, dot, underscore or hyphen.')
    }

    $parsedVersion = $null
    if (-not [version]::TryParse((([string]$ScriptVersion -split '-')[0]), [ref]$parsedVersion)) {
        $problems.Add('ScriptVersion must look like 1.2.3 (an optional -suffix is allowed).')
    }

    foreach ($name in 'UpdateCheckUrl', 'TelemetryUrl') {
        $value = [string](Get-Variable -Name $name -ValueOnly -ErrorAction SilentlyContinue)
        if ($value -notmatch '^https://') {
            $problems.Add(('{0} must be an https:// address.' -f $name))
        }
    }

    if ([string]::IsNullOrWhiteSpace($NetworkUserAgent)) { $problems.Add('NetworkUserAgent must not be empty.') }
    if ([string]::IsNullOrWhiteSpace($EventLogSource)) { $problems.Add('EventLogSource must not be empty.') }
    if ($LogMaxSizeMB -lt 0 -or $LogArchivesToKeep -lt 0) { $problems.Add('LogMaxSizeMB and LogArchivesToKeep must not be negative.') }

    return $problems.ToArray()
}

function Get-RunMode {
    <#
    .SYNOPSIS
        Returns 'interactive' or 'unattended'.
    .DESCRIPTION
        Unattended means no prompt may ever be shown: no user session, -NonInteractive
        was passed, or input is redirected. A script can set $script:RunMode itself
        before this template runs to override the detection.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $nonInteractiveFlag = @([Environment]::GetCommandLineArgs() | Where-Object { $_ -like '-noni*' }).Count -gt 0

    if (-not [Environment]::UserInteractive -or $nonInteractiveFlag -or [Console]::IsInputRedirected) {
        return 'unattended'
    }
    return 'interactive'
}

function Resolve-LogLevel {
    <#
    .SYNOPSIS
        Converts a level name or number to its numeric value, or returns -1 if invalid.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([string]$Value)

    $text = $Value.Trim().ToUpper()

    if ($logLevelMap.ContainsKey($text)) { return [int]$logLevelMap[$text] }

    $number = 0
    if ([int]::TryParse($text, [ref]$number) -and $number -ge 0 -and $number -le 7) {
        if ($number -eq 0) { return [int]$logLevelMap['NONE'] }
        return $number
    }
    return -1
}

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
function Invoke-LogRotation {
    <#
    .SYNOPSIS
        Rotates the log file when it has grown past the size limit.
    .DESCRIPTION
        Name.log becomes Name.1.log, Name.1.log becomes Name.2.log, and so on. The oldest
        copy beyond $LogArchivesToKeep is deleted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [int]$MaxSizeMB,
        [int]$Keep
    )

    if ($MaxSizeMB -le 0 -or $Keep -le 0) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    if ((Get-Item -LiteralPath $Path).Length -lt ($MaxSizeMB * 1MB)) { return }

    $folder = Split-Path -Path $Path -Parent
    $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $ext = [System.IO.Path]::GetExtension($Path)

    for ($i = $Keep; $i -ge 1; $i--) {
        if ($i -eq 1) { $source = $Path }
        else { $source = Join-Path -Path $folder -ChildPath ('{0}.{1}{2}' -f $base, ($i - 1), $ext) }
        $target = Join-Path -Path $folder -ChildPath ('{0}.{1}{2}' -f $base, $i, $ext)

        if (Test-Path -LiteralPath $source) {
            if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force -ErrorAction Stop -WhatIf:$false }
            Move-Item -LiteralPath $source -Destination $target -Force -ErrorAction Stop -WhatIf:$false
        }
    }
}

function Initialize-ToolLogging {
    <#
    .SYNOPSIS
        Creates the log folder and file, rotating first if needed.
    .DESCRIPTION
        The file is created read-only to discourage accidental edits. Write-LogFile uses
        -Force to write past that attribute. Failure to create the log is a failed run.
        Logging is never gated behind WhatIf, so -WhatIf runs are logged too.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Logging is not available yet, so errors go straight to the console.')]
    [CmdletBinding()]
    param()

    try {
        $logFolder = Split-Path -Path $Script:LogPath -Parent
        [void][System.IO.Directory]::CreateDirectory($logFolder)

        try {
            Invoke-LogRotation -Path $Script:LogPath -MaxSizeMB $LogMaxSizeMB -Keep $LogArchivesToKeep
        }
        catch {
            Write-Host ('Log rotation failed, continuing with the current file: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
        }

        if (-not (Test-Path -LiteralPath $Script:LogPath -PathType Leaf)) {
            [System.IO.File]::Create($Script:LogPath).Dispose()
            Set-ItemProperty -LiteralPath $Script:LogPath -Name IsReadOnly -Value $true -WhatIf:$false
        }
    }
    catch {
        Write-Host ('Unable to create the log file {0}: {1}' -f $Script:LogPath, $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}

function Write-LogFile {
    <#
    .SYNOPSIS
        Writes a message to the log file, subject to the configured logging level.
    .DESCRIPTION
        Appends a timestamped, level-tagged, single-line entry. The message is only written
        if its level is at or above $Script:LogThreshold. Secrets are masked first when
        $RedactLogSecrets is on.
    .PARAMETER message
        The text to log.
    .PARAMETER level
        Debug, Verbose, Info, Warn, Error or Critical.
    .EXAMPLE
        Write-LogFile -level Info -message 'Scan completed successfully.'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$message,
        [Parameter(Mandatory)]
        [ValidateSet('Debug', 'Verbose', 'Info', 'Warn', 'Error', 'Critical')]
        [string]$level
    )

    $levelName = $level.ToUpper()
    if ($logLevelMap[$levelName] -ge $Script:LogThreshold) {
        $singleLine = (Protect-LogText -Text $message) -replace '[\r\n]+', ' '
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $line = '{0} | [{1}] | {2}' -f $timestamp, $levelName, $singleLine
        Add-Content -LiteralPath $Script:LogPath -Value $line -Encoding UTF8 -Force -ErrorAction Stop -WhatIf:$false
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Logs a message to the log file and echoes it to the console.
    .DESCRIPTION
        Calls Write-LogFile, then echoes the same message to the console if its level meets
        the logging threshold. -Success only changes the console colour. The entry is still
        logged at the level supplied. Never gated behind WhatIf: logging always runs.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Console output is intentional; the log file is the durable record.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [ValidateSet('Debug', 'Verbose', 'Info', 'Warn', 'Error', 'Critical')]
        [string]$Level = 'Info',

        [switch]$Success
    )

    $safeMessage = Protect-LogText -Text $Message

    try {
        Write-LogFile -level $Level -message $safeMessage
    }
    catch {
        Write-Host ('[LOGGING FAILURE] {0}' -f $_.Exception.Message) -ForegroundColor Red
    }

    if ($logLevelMap[$Level.ToUpper()] -ge $Script:LogThreshold) {
        $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level.ToUpper(), $safeMessage

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

# ------------------------------------------------------------------------------
# Windows event log
# ------------------------------------------------------------------------------
function Initialize-EventLogSource {
    <#
    .SYNOPSIS
        Registers the event source if possible and records whether event writes will work.
    .DESCRIPTION
        Registration needs an elevated session, and the event log cmdlets do not exist in
        PowerShell 7. Either way the scan carries on and event writes are skipped.
    #>
    [CmdletBinding()]
    param()

    $Script:eventLogReady = $false

    if (-not (Get-Command -Name Write-EventLog -ErrorAction SilentlyContinue)) {
        Write-LogFile -level Debug -message 'Event log cmdlets are not available in this PowerShell edition. Event log writes are skipped.'
        return
    }

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
            New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
        }
        $Script:eventLogReady = $true
    }
    catch {
        Write-LogFile -level Warn -message "Could not register event log source '$EventLogSource': $($_.Exception.Message). Event log writes will be skipped until this is resolved (requires an elevated session)."
    }
}

function Write-LogEvent {
    <#
    .SYNOPSIS
        Writes an entry to the Windows Application Event Log.
    .DESCRIPTION
        Wraps Write-EventLog under the script's registered source. Used for the subset of
        conditions worth surfacing to central monitoring, distinct from the full file log.
    .PARAMETER eventID
        The event ID to log. See the tool README for the event ID map.
    .PARAMETER entryType
        Error, Warning, Information, SuccessAudit or FailureAudit.
    .EXAMPLE
        Write-LogEvent -eventID 3010 -entryType Error -message 'Entra app expiry scan failed.'
    #>
    [CmdletBinding()]
    param (
        [string]$logSource = $EventLogSource,
        [string]$logName = $EventLogName,
        [Parameter(Mandatory)]
        [string]$message,
        [Parameter(Mandatory)]
        [int]$eventID,
        [Parameter(Mandatory)]
        [System.Diagnostics.EventLogEntryType]$entryType
    )

    # Event messages are capped by Windows at roughly 31,800 characters.
    $text = Protect-LogText -Text $message
    if ($text.Length -gt 30000) { $text = $text.Substring(0, 30000) }

    Write-EventLog -LogName $logName -Source $logSource -EntryType $entryType -Category 0 -EventId $eventID -Message $text
}

function Send-LogEvent {
    <#
    .SYNOPSIS
        Writes an Application event log entry if the event source is available.
    .DESCRIPTION
        Wraps Write-LogEvent so a missing event source never stops the scan. Failures are
        logged as Warn.
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

# ------------------------------------------------------------------------------
# Report folder and retention
# ------------------------------------------------------------------------------
function Initialize-OutputFolder {
    <#
    .SYNOPSIS
        Creates the report folder, refusing a drive root.
    #>
    [CmdletBinding()]
    param()

    # Folder creation is deliberately not gated: reports need somewhere to go.
    $root = [System.IO.Path]::GetPathRoot($Script:ReportPath)
    if ($Script:ReportPath.TrimEnd('\', '/') -eq $root.TrimEnd('\', '/')) {
        throw ('ReportPath {0} is a drive root. Choose a subfolder.' -f $Script:ReportPath)
    }

    [void][System.IO.Directory]::CreateDirectory($Script:ReportPath)
}

function Remove-ExpiredOutput {
    <#
    .SYNOPSIS
        Removes this tool's old .csv and .html reports.
    .DESCRIPTION
        Only files named "<ScriptName>_*" are considered, so other files in the folder are
        never touched. Drive roots are refused.
    #>
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
    $namePattern = '{0}_*' -f $ScriptName
    $removed = 0

    foreach ($path in $Folder) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            Write-Log 'Retention cleanup skipped: the folder path is empty.' -Level Warn
            continue
        }

        $root = [System.IO.Path]::GetPathRoot($path)
        if ($path.TrimEnd('\', '/') -eq $root.TrimEnd('\', '/')) {
            Write-Log ('Retention cleanup skipped for {0}: it is a drive root.' -f $path) -Level Warn
            continue
        }

        try {
            $oldFiles = Get-ChildItem -LiteralPath $path -File -ErrorAction Stop |
                Where-Object { $_.LastWriteTime -lt $cutoff -and $_.Name -like $namePattern -and $_.Extension -in '.csv', '.html' }

            foreach ($file in $oldFiles) {
                if ($PSCmdlet.ShouldProcess($file.FullName, 'Remove report past retention period')) {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
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
# Update check and telemetry
# Both run after the scan, are optional, and can never affect its result. Every
# failure is logged at Debug and ignored. Nothing is downloaded or installed.
# ------------------------------------------------------------------------------
function Enable-ModernTls {
    <#
    .SYNOPSIS
        Makes sure TLS 1.2 is allowed on Windows PowerShell 5.1. PowerShell 7 needs nothing.
    #>
    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSEdition -ne 'Core') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
}

function Get-LatestToolVersion {
    <#
    .SYNOPSIS
        Reads the latest published version of this tool from the static version file.
    .DESCRIPTION
        Makes a plain GET request with a generic User-Agent and sends no data. Remote
        values are cleaned before use. Returns $null if the check fails for any reason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    try {
        Enable-ModernTls
        $response = Invoke-RestMethod -Uri $UpdateCheckUrl -Method Get -TimeoutSec 5 -UserAgent $NetworkUserAgent -ErrorAction Stop
        $entry = $response.tools.$ScriptName

        if (-not $entry) {
            Write-Log ('Update check: {0} is not listed in the version file.' -f $ScriptName) -Level Debug
            return $null
        }

        $latestText = Limit-Text -Text ([string]$entry.version) -Max 32
        $latest = [version](($latestText -split '-')[0])
        $current = [version](($ScriptVersion -split '-')[0])

        return [pscustomobject]@{
            Version  = $latestText
            Released = Limit-Text -Text ([string]$entry.released) -Max 32
            Url      = Limit-Text -Text ([string]$entry.url) -Max 300
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
        Tells the user a newer version exists and, in an interactive session only, offers to
        open the release page.
    .DESCRIPTION
        The link is only shown and opened if it matches $UpdateUrlAllowPattern, in case the
        version file were ever tampered with.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Latest
    )

    $urlIsSafe = $Latest.Url -match $UpdateUrlAllowPattern

    if ($urlIsSafe) {
        Write-Log ('Update available: {0} {1} (you have {2}). Release page: {3}' -f $ScriptName, $Latest.Version, $ScriptVersion, $Latest.Url)
    }
    else {
        Write-Log ('Update available: {0} {1} (you have {2}). The version file gave no trusted release link, so none is shown.' -f $ScriptName, $Latest.Version, $ScriptVersion) -Level Warn
    }

    # Never prompt in unattended runs or dry runs.
    if ($script:RunMode -ne 'interactive' -or $WhatIfPreference -or -not $urlIsSafe) {
        return
    }

    $answer = Read-Host 'Open the release page in your browser now? (y/N)'
    if ($answer.Trim().ToLower() -in 'y', 'yes') {
        Start-Process -FilePath $Latest.Url
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

        if ($PSVersionTable.PSEdition -eq 'Core') { $_psEdition = 'Core' } else { $_psEdition = 'Desktop' }

        $payload = [ordered]@{
            tool      = $ScriptName
            version   = $ScriptVersion
            os        = Limit-Text -Text $osCaption -Max 64
            osBuild   = Limit-Text -Text $osBuild -Max 32
            psVersion = Limit-Text -Text $PSVersionTable.PSVersion.ToString() -Max 32
            psEdition = $_psEdition
            timezone  = Limit-Text -Text ([TimeZoneInfo]::Local.Id) -Max 64
            runMode   = $script:RunMode
        }

        $json = $payload | ConvertTo-Json -Compress
        Write-Log ('Telemetry payload: {0}' -f $json) -Level Debug

        if ($PSCmdlet.ShouldProcess($TelemetryUrl, 'Send anonymous usage telemetry')) {
            Enable-ModernTls
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
    <#
    .SYNOPSIS
        Runs the optional update check and telemetry. Call it last in the script.
    .DESCRIPTION
        Telemetry is on by default (opt-out). It is skipped if -DisableTelemetry is used or
        either the tool's opt-out variable or DO_NOT_TRACK is set to 1 or true.
    #>
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

    $toolOptOut = [Environment]::GetEnvironmentVariable($TelemetryOptOutEnvVar)
    $doNotTrack = [Environment]::GetEnvironmentVariable('DO_NOT_TRACK')
    $telemetryOff = $DisableTelemetry -or ($toolOptOut -in '1', 'true') -or ($doNotTrack -in '1', 'true')

    if ($telemetryOff) {
        Write-Log 'Telemetry disabled.' -Level Debug
    }
    else {
        Write-Log ('Anonymous usage telemetry is on. Disable it with -DisableTelemetry, {0}=1 or DO_NOT_TRACK=1. See {1} in the repository root.' -f $TelemetryOptOutEnvVar, $TelemetryDocName)
        Send-ToolTelemetry
    }
}

# ------------------------------------------------------------------------------
# Initialisation (runs when the script starts)
# ------------------------------------------------------------------------------
$configProblems = @(Test-ToolConfig)
if ($configProblems.Count -gt 0) {
    foreach ($problem in $configProblems) {
        Write-Host ('Configuration error: {0}' -f $problem) -ForegroundColor Red
    }
    exit 1
}

$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# Apply CONFIG defaults for anything not supplied, then resolve to full paths. The
# PowerShell location is used for relative paths, not the .NET working directory.
if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = $DefaultLogPath }
if ([string]::IsNullOrWhiteSpace($ReportPath)) { $ReportPath = $DefaultReportPath }
if (-not $PSBoundParameters.ContainsKey('RetentionDays')) { $RetentionDays = $DefaultRetentionDays }
$LogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
$ReportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)

# Run mode: a script may preset $script:RunMode to override detection.
if ($null -eq (Get-Variable -Name RunMode -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) {
    $script:RunMode = Get-RunMode
}

# Logging level: an explicit -LoggingLevel wins, then -Debug or -Verbose, then the default.
$defaultLevelName = $DefaultLoggingLevel
if ($VerbosePreference -ne 'SilentlyContinue') { $defaultLevelName = 'VERBOSE' }
if ($DebugPreference -ne 'SilentlyContinue') { $defaultLevelName = 'DEBUG' }

if ([string]::IsNullOrWhiteSpace($LoggingLevel)) { $requestedLevel = $defaultLevelName } else { $requestedLevel = $LoggingLevel }

$resolvedLevel = Resolve-LogLevel -Value $requestedLevel
$levelWarning = $null
if ($resolvedLevel -lt 1) {
    $levelWarning = 'Unrecognised logging level "{0}". Using INFO.' -f (Limit-Text -Text $requestedLevel -Max 32)
    $resolvedLevel = $logLevelMap['INFO']
}
$Script:LogThreshold = $resolvedLevel
$levelName = $logLevelMap.Keys | Where-Object { $logLevelMap[$_] -eq $Script:LogThreshold } | Select-Object -First 1

Initialize-ToolLogging
Initialize-EventLogSource

if ($levelWarning) { Write-Log $levelWarning -Level Warn }

Write-LogFile -level Verbose -message 'Logging has been configured'
Write-LogFile -level Debug -message ('logPath={0}; eventLogSource={1}; eventLogName={2}; template={3}; runMode={4}' -f $LogPath, $EventLogSource, $EventLogName, $TemplateVersion, $script:RunMode)
Write-LogFile -level Info -message ('{0} {1} starting - logging level is {2}' -f $ScriptName, $ScriptVersion, $levelName)
#endregion PC-TEMPLATE v1.1.1

# ==============================================================================
# Script body starts here
# ==============================================================================

##################################################
# Variables
##################################################
$configPath = ".\config.psd1"
$config = Import-PowerShellDataFile -Path $configPath -ErrorAction SilentlyContinue

$tenantID = $config.TenantId
$applicationID = $config.ClientId
$applicationThumbprint = $config.clientThumbprint

# Daily audit CSV, named so the template's retention cleanup recognises it. The state
# file sits beside it and is never touched by retention (it is not a .csv or .html).
$reportFile = Join-Path -Path $ReportPath -ChildPath ('{0}_{1}.csv' -f $ScriptName, (Get-Date -Format 'yyyyMMdd'))
$stateFilePath = Join-Path -Path $ReportPath -ChildPath 'BlockedUsers.psd1'
$legacyStateFilePath = 'C:\Pickering-Cloud\Reports\OWAManagement\BlockedUsers.psd1'

$mailboxGrantingSkuParts = @(
    "EXCHANGESTANDARD",
    "EXCHANGEENTERPRISE",
    "ENTERPRISEPACK",
    "ENTERPRISEPREMIUM",
    "STANDARDPACK",
    "SPE_E3",
    "SPE_E5",
    "SPB",
    "EDUCATION"
)

$owaClientParameters = @(
    "OWAEnabled",
    "OWAforDevicesEnabled",
    "OutlookMobileEnabled",
    "MacOutlookEnabled",
    "OneWinNativeOutlookEnabled"
)

##################################################
# Reporting
##################################################

function Exit-WithError {
    <#
    .SYNOPSIS
        Logs a Critical message, optionally writes an Error event, and exits with code 1.
    .DESCRIPTION
        Replaces the pre-template behaviour where Write-Log -Level CRITICAL also exited
        the script. The main body runs inside try/finally, so the update check and
        telemetry still run on this exit path.
    .PARAMETER Message
        The reason the run failed.
    .PARAMETER EventId
        Optional Application event ID to write as an Error entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [int]$EventId = 0
    )

    Write-Log $Message -Level Critical
    if ($EventId -gt 0) {
        Send-LogEvent -EventId $EventId -EntryType Error -Message $Message
    }
    exit 1
}

function Write-Report {
    <#
        .SYNOPSIS
            Appends a Blocked/Unblocked audit entry to the daily CSV report.

        .DESCRIPTION
            Records a single OWA block or unblock action, with timestamp, user
            details, and reason, to the CSV report at $reportFile. This is the
            audit trail deliverable for the script - separate from the persistent
            state file, which only tracks current state rather than history.

        .PARAMETER UserPrincipalName
            UPN of the affected user.

        .PARAMETER DisplayName
            Display name of the affected user, for readability in the report.

        .PARAMETER Action
            Either "Blocked" or "Unblocked".

        .PARAMETER Reason
            Free-text reason for the action, e.g. "F1 Licence" or "Licence no
            longer requires OWA block". Optional, defaults to an empty string.

        .EXAMPLE
            Write-Report -UserPrincipalName 'jo@contoso.com' -DisplayName 'Jo Bloggs' -Action 'Blocked' -Reason 'F1 Licence'

            Appends a single row to the CSV report for this action.

        .OUTPUTS
            None. Appends a row to the CSV report file at $reportFile.

        .NOTES
            Called internally by Block-UserOWA and Unblock-UserOWA. The report
            folder is created by Initialize-OutputFolder at the start of the run.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory)]
        [string]$DisplayName,
        [Parameter(Mandatory)]
        [ValidateSet("Blocked", "Unblocked")]
        [string]$Action,
        [string]$Reason = ""
    )

    Write-Log "Running Write-Report" -Level DEBUG

    $entry = [PSCustomObject]@{
        Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        UserPrincipalName = $UserPrincipalName
        DisplayName       = $DisplayName
        Action            = $Action
        Reason            = $Reason
    }

    Try {
        $entry | Export-Csv -Path $reportFile -Append -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
    }
    Catch {
        Write-Log -Message "Failed to write report entry for $UserPrincipalName : $($_.Exception.Message)" -Level ERROR
    }
}

##################################################
# Functions
##################################################

function Test-Config {
    <#
        .SYNOPSIS
            Ensures a config file exists before the script attempts to read one.

        .DESCRIPTION
            Checks for the presence of the config file at $configPath. If missing,
            calls Write-DefaultConfig to create a blank template and exit, so a
            first-time run doesn't proceed with an unconfigured tenant.

        .EXAMPLE
            Test-Config

            Creates a default config file and exits if $configPath doesn't exist;
            otherwise does nothing.

        .OUTPUTS
            None.

        .NOTES
            Relies on the script-scoped $configPath variable.
    #>
    Write-Log "Running Test-Config" -Level DEBUG
    
    if (-not (Test-Path $configPath)) {
        Write-DefaultConfig
    }

}

function Write-DefaultConfig {
    <#
        .SYNOPSIS
            Writes a blank template config file and exits.

        .DESCRIPTION
            Creates a config.psd1 with empty TenantId, ClientId, and
            ClientThumbprint values, then exits the script immediately so the
            admin can populate it (or run with -Setup) before the next run.

        .EXAMPLE
            Write-DefaultConfig

            Writes the template config file to $configPath and exits with code 0.

        .OUTPUTS
            None. Writes the config file to disk and exits the script.

        .NOTES
            Called internally by Test-Config when no config file is found. Relies
            on the script-scoped $configPath variable.
    #>
    Write-Log "Running Write-DefaultConfig" -Level DEBUG
    
    $configData = @"
@{
    TenantId            = ""
    ClientId            = ""
    ClientThumbprint    = ""

}
"@
    
    Set-Content -Path $configPath -Value $configData -Encoding UTF8
    Write-Log -Message "Default config file created."
    exit 0

}

function Update-Config {
    <#
        .SYNOPSIS
            Writes new service principal details to the config file.

        .DESCRIPTION
            Overwrites the config file at $configPath with the supplied TenantId,
            ClientId, and ClientThumbprint values, typically after interactive
            service principal creation via New-OWAServicePrincipal.

        .PARAMETER TenantId
            Entra tenant ID to persist to the config file.

        .PARAMETER ClientId
            Application (client) ID of the service principal to persist.

        .PARAMETER ClientThumbprint
            Certificate thumbprint of the service principal's authentication
            certificate to persist.

        .EXAMPLE
            Update-Config -TenantId $spDetails.TenantId -ClientId $spDetails.ClientId -ClientThumbprint $spDetails.ClientThumbprint

            Writes the newly created service principal's details to the config file.

        .OUTPUTS
            None. Writes the config file to disk.

        .NOTES
            Called internally by Connect-TenantMG after New-OWAServicePrincipal
            completes. Relies on the script-scoped $configPath variable.
    #>
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientThumbprint
    )
    Write-Log "Running Update-Config" -Level DEBUG

    $configData = @"
@{
    TenantId            = '$TenantId'
    ClientId            = '$ClientId'
    ClientThumbprint    = '$ClientThumbprint'

}
"@

    Set-Content -Path $configPath -Value $configData -Encoding UTF8
    Write-Log -Message "Config file updated with generated values."

}

function Test-RequiredModules {
    <#
        .SYNOPSIS
            Ensures required PowerShell modules are imported, installing any that are missing.

        .DESCRIPTION
            Attempts to import each named module. If a module isn't already
            installed, installs it from the PowerShell Gallery before importing.
            Intended to be called once near the top of the script with the full
            list of modules this script depends on.

        .PARAMETER Modules
            Array of module names to ensure are imported.

        .EXAMPLE
            Test-RequiredModules -Modules @("Microsoft.Graph.Authentication", "ExchangeOnlineManagement")

            Imports both modules, installing either one first if not already present.

        .OUTPUTS
            None.

        .NOTES
            Install-Module here uses the default (AllUsers) install scope, which
            typically requires an elevated session. Consider adding -Scope
            CurrentUser if this needs to run without admin rights.
    #>
    param (
        [array]$Modules
    )
    Write-Log "Running Test-RequiredModules" -Level DEBUG

    foreach ($module in $modules) {
        Try {
            Import-Module -Name $module -Force -ErrorAction Stop
        }
        Catch {
            Write-Log "Installing module: $module."
            Install-Module -Name $module -Scope CurrentUser -Force
            Import-Module -Name $module -Force
        }
    }
}

function Connect-TenantMG {
    <#
        .SYNOPSIS
            Connects to Microsoft Graph using the configured service principal, provisioning one first if needed.

        .DESCRIPTION
            Checks whether a usable service principal is already configured via
            Test-ServicePrincipalDetails. If not, and -Setup was passed to the
            script, runs New-OWAServicePrincipal to create one interactively,
            persists the result via Update-Config, and updates the script-scoped
            credential variables in memory before continuing. If a service
            principal isn't configured and -Setup wasn't passed, logs a CRITICAL
            error and exits rather than attempting an interactive sign-in during
            what's meant to be an unattended run.

        .EXAMPLE
            Connect-TenantMG

            Connects to Graph using the existing service principal, or exits with
            guidance if none is configured and -Setup wasn't passed.

        .OUTPUTS
            None. Establishes a Microsoft Graph session for the rest of the script.

        .NOTES
            Relies on the script-scoped $Setup switch and $tenantID,
            $applicationID, $applicationThumbprint variables.
    #>
    Write-Log "Running Connect-TenantMG" -Level DEBUG
    if (-not (Test-ServicePrincipalDetails)) {
        if (-not $Setup) {
            Exit-WithError "Service principal not configured. Re-run with -Setup to provision it interactively."
        }

        $spDetails = New-OWAServicePrincipal
        if ($null -eq $spDetails) {
            Exit-WithError "Service principal setup did not complete - aborting."
        }

        Update-Config -TenantId $spDetails.TenantId -ClientId $spDetails.ClientId -ClientThumbprint $spDetails.ClientThumbprint

        Write-Log -Message "New service principal created. Certificate trust and role assignment can take several minutes to propagate - if the next step fails to connect to Exchange Online, wait a few minutes and re-run the script." -Level WARN

        $script:tenantID = $spDetails.TenantId
        $script:applicationID = $spDetails.ClientId
        $script:applicationThumbprint = $spDetails.ClientThumbprint
    }

    Connect-MgGraph -ClientId $applicationID -TenantId $tenantID -CertificateThumbprint $applicationThumbprint -NoWelcome
    Write-Log -Message "Connected to tenant: $tenantID using application: $applicationID."
}

function Connect-TenantEXO {
    <#
        .SYNOPSIS
            Connects to Exchange Online using the configured service principal.

        .DESCRIPTION
            Resolves the tenant's initial (.onmicrosoft.com) domain via Graph,
            since certificate-based app-only auth for Exchange Online requires
            that domain rather than the tenant GUID, then connects using the
            service principal's certificate.

        .EXAMPLE
            Connect-TenantEXO

            Connects to Exchange Online for the current tenant.

        .OUTPUTS
            None. Establishes an Exchange Online PowerShell session for the rest
            of the script.

        .NOTES
            Must be called after Connect-TenantMG, since it depends on an active
            Graph session to resolve the tenant's initial domain. If this service
            principal was created recently, connection failure here can be caused
            by Entra role and certificate propagation delay - wait a few minutes
            and re-run.
    #>
    Write-Log "Running Connect-TenantEXO" -Level DEBUG
    Try {
        $initialDomain = (Get-MgOrganization).VerifiedDomains | Where-Object { $_.IsInitial } | Select-Object -ExpandProperty Name
    }
    Catch {
        Exit-WithError "Failed to retrieve tenant initial domain: $($_.Exception.Message)"
    }

    Try {
        Connect-ExchangeOnline -AppId $applicationID -CertificateThumbprint $applicationThumbprint -Organization $initialDomain -ShowBanner:$false -ErrorAction Stop
        Write-Log -Message "Connected to Exchange Online for tenant: $initialDomain."
    }
    Catch {
        Write-Log -Message "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level ERROR
        Exit-WithError "If this service principal was created recently, this can be caused by Entra role and certificate propagation delay - wait a few minutes and try again before investigating further."
    }
}

function Test-ServicePrincipalDetails {
    <#
        .SYNOPSIS
            Checks whether the service principal's credentials are fully populated.

        .DESCRIPTION
            Returns $false if TenantId or ClientId are missing. Returns $true if
            all three values (TenantId, ClientId, ClientThumbprint) are present.
            If TenantId and ClientId are present but the certificate thumbprint is
            missing, logs a CRITICAL error and exits, since a missing thumbprint
            specifically indicates an incompletely edited config file rather than
            an unconfigured one.

        .EXAMPLE
            Test-ServicePrincipalDetails

            Returns $true or $false depending on whether the service principal is
            fully configured.

        .OUTPUTS
            System.Boolean

        .NOTES
            Relies on the script-scoped $tenantID, $applicationID, and
            $applicationThumbprint variables.
    #>
    Write-Log "Running Test-ServicePrincipalDetails" -Level DEBUG
    if ([string]::IsNullOrWhiteSpace($applicationID) -or [string]::IsNullOrWhiteSpace($tenantID)) {
        return $false
    }
    elseif ([string]::IsNullOrWhiteSpace($applicationThumbprint)) {
        Exit-WithError "No certificate thumbprint provided - please update $configPath."
    }
    else {
        return $true
    }
}

function New-OWAServicePrincipal {
    <#
        .SYNOPSIS
            Creates and configures the Entra app registration and service principal used for unattended OWA management.

        .DESCRIPTION
            Interactive, one-time setup. Connects to Microsoft Graph with
            delegated admin permissions, creates a self-signed certificate for
            app-only authentication, registers a new Entra application and
            service principal, attaches the certificate, and grants the
            permissions the unattended script needs: Graph application
            permissions User.Read.All and Organization.Read.All, the Exchange
            Online application permission Exchange.ManageAsApp, and the Exchange
            Administrator Entra directory role (required for Set-CASMailbox to
            work under app-only auth; Exchange.ManageAsApp alone is not
            sufficient). If TenantId is already known (populated in config), the
            interactive sign-in is pinned to that tenant explicitly, so an admin
            with access to multiple tenants can't accidentally create the app
            registration in the wrong one.

            Must be run manually by an admin holding Application Administrator
            (or Global Administrator) and Privileged Role Administrator rights.
            Not part of the unattended job - only ever invoked via Connect-TenantMG
            when the script is run with -Setup and no service principal is yet
            configured.

        .PARAMETER AppDisplayName
            Display name for the new Entra application registration. Defaults to
            "OWA-Manage-F1-Automation".

        .PARAMETER CertSubject
            Subject name for the self-signed authentication certificate. Defaults
            to "CN=OWAManageAutomation".

        .PARAMETER CertValidityYears
            Validity period, in years, for the self-signed certificate. Defaults
            to 2.

        .EXAMPLE
            New-OWAServicePrincipal

            Runs the full interactive setup with default naming, returning the
            new service principal's TenantId, ClientId, and ClientThumbprint.

        .EXAMPLE
            New-OWAServicePrincipal -AppDisplayName 'OWA-Block-Prod' -CertValidityYears 3

            Runs setup with a custom app name and a 3-year certificate validity.

        .OUTPUTS
            System.Management.Automation.PSCustomObject with properties
            TenantId, ClientId, ClientThumbprint on success, or $null if any step
            fails (each failure is logged with -Level ERROR before returning).

        .NOTES
            Admin consent for the granted application permissions must still be
            confirmed manually in the Entra portal before the first unattended
            run - this function assigns the app roles but does not grant consent,
            since that's a separate, explicit consent action.
    #>
    param(
        [string]$AppDisplayName = "OWA-Manage-F1-Automation",
        [string]$CertSubject    = "CN=OWAManageAutomation",
        [int]$CertValidityYears = 2
    )
    Write-Log "Running New-OWAServicePrincipal" -Level DEBUG
    Write-Log -Message "Starting interactive service principal setup."

    Try {
        if ([string]::IsNullOrWhiteSpace($tenantID)) {
            Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory" -NoWelcome -ErrorAction Stop
        }
        else {
            Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory" -TenantId $tenantID -NoWelcome -ErrorAction Stop
        }
    }
    Catch {
        Write-Log -Message "Failed to connect to Graph for SP setup: $($_.Exception.Message)" -Level ERROR
        return
    }

    if ($null -eq $tenantId) {
        $tenantId = (Get-MgOrganization).Id
    }
    Write-Log -Message "Connected to tenant $tenantId."

    # Certificate for app-only auth. Certs, not client secrets, are required for Exchange Online app-only auth.
    Try {
        $cert = New-SelfSignedCertificate -Subject $CertSubject -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -NotAfter (Get-Date).AddYears($CertValidityYears)
        Write-Log -Message "Self-signed certificate created with thumbprint $($cert.Thumbprint)."
    }
    Catch {
        Write-Log -Message "Certificate creation failed: $($_.Exception.Message)" -Level ERROR
        return
    }

    # App registration and service principal
    Try {
        $app = New-MgApplication -DisplayName $AppDisplayName -SignInAudience "AzureADMyOrg"
        $sp  = New-MgServicePrincipal -AppId $app.AppId
        Write-Log -Message "App registration ($($app.AppId)) and service principal created."
    }
    Catch {
        Write-Log -Message "App registration/SP creation failed: $($_.Exception.Message)" -Level ERROR
        return
    }

    # Attach certificate public key to the app
    Try {
        $keyCred = @{
            Type  = "AsymmetricX509Cert"
            Usage = "Verify"
            Key   = $cert.RawData
        }
        Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCred)
        Write-Log -Message "Certificate attached to app registration."
    }
    Catch {
        Write-Log -Message "Failed to attach certificate to app: $($_.Exception.Message)" -Level ERROR
        return
    }

    # --- Microsoft Graph permission: User.Read.All (read licenses) ---
    Try {
        $graphSpId = (Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'").Id
        $graphAppRole = (Get-MgServicePrincipal -ServicePrincipalId $graphSpId).AppRoles |
            Where-Object { $_.Value -eq "User.Read.All" }

        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id `
            -ResourceId $graphSpId -AppRoleId $graphAppRole.Id | Out-Null

        Write-Log -Message "Granted Graph application permission User.Read.All."
    }
    Catch {
        Write-Log -Message "Failed to grant Graph permission: $($_.Exception.Message)" -Level ERROR
        return
    }

    # --- Microsoft Graph permission: Organization.Read.All (read subscribed skus) ---
    Try {
        $graphSpId = (Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'").Id
        $graphAppRole = (Get-MgServicePrincipal -ServicePrincipalId $graphSpId).AppRoles |
            Where-Object { $_.Value -eq "Organization.Read.All" }

        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id `
            -ResourceId $graphSpId -AppRoleId $graphAppRole.Id | Out-Null

        Write-Log -Message "Granted Graph application permission Organization.Read.All."
    }
    Catch {
        Write-Log -Message "Failed to grant Graph permission: $($_.Exception.Message)" -Level ERROR
        return
    }

    # --- Exchange Online permission: Exchange.ManageAsApp (enable/disable OWA) ---
    Try {
        $exoSpId = (Get-MgServicePrincipal -Filter "AppId eq '00000002-0000-0ff1-ce00-000000000000'").Id
        $exoAppRole = (Get-MgServicePrincipal -ServicePrincipalId $exoSpId).AppRoles |
            Where-Object { $_.Value -eq "Exchange.ManageAsApp" }

        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id `
            -ResourceId $exoSpId -AppRoleId $exoAppRole.Id | Out-Null

        Write-Log -Message "Granted Exchange Online application permission Exchange.ManageAsApp."
    }
    Catch {
        Write-Log -Message "Failed to grant Exchange.ManageAsApp permission: $($_.Exception.Message)" -Level ERROR
        return
    }

    # --- Directory role: Exchange Administrator ---
    # Exchange.ManageAsApp alone is not sufficient for Set-CASMailbox as an app;
    # the SP also needs the Exchange Administrator directory role assigned.
    Try {
        $roleName = "Exchange Administrator"
        $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$roleName'"

        New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $sp.Id -RoleDefinitionId $roleDef.Id `
            -DirectoryScopeId "/" | Out-Null

        Write-Log -Message "Assigned Exchange Administrator directory role to service principal."
    }
    Catch {
        Write-Log -Message "Failed to assign Exchange Administrator role: $($_.Exception.Message)" -Level ERROR
        return
    }

    Write-Log -Message "Service principal setup complete. AppId=$($app.AppId), TenantId=$tenantId, Thumbprint=$($cert.Thumbprint)."
    Write-Log -Message "Admin consent for application permissions must still be confirmed in the Entra portal before first unattended run." -Level WARN

    Disconnect-MgGraph

    return [PSCustomObject]@{
        TenantId         = $tenantId
        ClientId         = $app.AppId
        ClientThumbprint = $cert.Thumbprint
    }
}

function Get-TenantSkuMap {
    <#
        .SYNOPSIS
            Retrieves all subscribed SKUs in the tenant as a SkuId-to-SkuPartNumber lookup.

        .DESCRIPTION
            Calls Get-MgSubscribedSku once and builds a hashtable keyed by SkuId,
            so downstream functions (Get-F1LicensedUsers, Get-OrphanedMailboxUsers)
            can resolve a user's assigned licence SKU IDs to human-readable part
            numbers without each making their own Graph call.

        .EXAMPLE
            Get-TenantSkuMap

            Returns a hashtable of all subscribed SKUs in the tenant, keyed by SkuId.

        .OUTPUTS
            System.Collections.Hashtable

        .NOTES
            Requires the Organization.Read.All Graph application permission.
    #>
    Write-Log "Running Get-TenantSkuMap" -Level DEBUG
    Try {
        $skus = Get-MgSubscribedSku -All -ErrorAction Stop
    }
    Catch {
        Exit-WithError "Failed to retrieve subscribed SKUs: $($_.Exception.Message)"
    }

    $skuMap = @{}
    foreach ($sku in $skus) {
        $skuMap[$sku.SkuId] = $sku.SkuPartNumber
    }

    Write-Log -Message "Retrieved $($skuMap.Count) subscribed SKU(s) from tenant."

    return $skuMap
}

function Get-AllTenantUsers {
    <#
        .SYNOPSIS
            Retrieves all users in the tenant with their assigned licences.

        .DESCRIPTION
            Calls Get-MgUser -All once for the whole run, so multiple downstream
            functions needing the full user list don't each trigger their own
            (potentially expensive) tenant-wide query.

        .EXAMPLE
            Get-AllTenantUsers

            Returns every user in the tenant with Id, DisplayName,
            UserPrincipalName, and AssignedLicenses populated.

        .OUTPUTS
            System.Object[] (Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser)

        .NOTES
            Requires the User.Read.All Graph application permission.
    #>
    Write-Log "Running Get-AllTenantUsers" -Level DEBUG
    Try {
        $allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AssignedLicenses -ErrorAction Stop
    }
    Catch {
        Exit-WithError "Failed to retrieve user list: $($_.Exception.Message)"
    }

    Write-Log -Message "Retrieved $($allUsers.Count) user(s) from tenant."

    return $allUsers
}

function Get-AllTenantMailboxes {
    <#
        .SYNOPSIS
            Retrieves all user mailboxes in the tenant.

        .DESCRIPTION
            Calls Get-EXOMailbox once for the whole run, restricted to
            RecipientTypeDetails UserMailbox so shared and room mailboxes (which
            have no licence by design) aren't flagged as orphaned later.
            UserPrincipalName is requested explicitly via -Properties, since
            Get-EXOMailbox's default minimal property set may not include it.

        .EXAMPLE
            Get-AllTenantMailboxes

            Returns every user mailbox in the tenant.

        .OUTPUTS
            System.Object[] (mailbox objects returned by Get-EXOMailbox)

        .NOTES
            Requires an active Exchange Online connection (Connect-TenantEXO).
    #>
    Write-Log "Running Get-AllTenantMailboxes" -Level DEBUG
    Try {
        $allMailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -Properties UserPrincipalName -ErrorAction Stop
    }
    Catch {
        Exit-WithError "Failed to retrieve mailboxes from Exchange Online: $($_.Exception.Message)"
    }

    Write-Log -Message "Retrieved $($allMailboxes.Count) mailbox(es) from Exchange Online."

    return $allMailboxes
}

function Get-F1LicensedUsers {
    <#
        .SYNOPSIS
            Finds users licensed with Microsoft 365 F1 or Office 365 F1.

        .DESCRIPTION
            Identifies the tenant's F1 SKU ID(s) (SPE_F1 or DESKLESSPACK) from the
            supplied SKU map, then filters the supplied user list to those with
            one of those SKUs in their AssignedLicenses. Returns an empty array
            (never $null) if no F1 SKU is found in the tenant or no users hold one.

        .PARAMETER SkuMap
            Hashtable of SkuId to SkuPartNumber, as returned by Get-TenantSkuMap.

        .PARAMETER AllUsers
            Full user list to filter, as returned by Get-AllTenantUsers.

        .EXAMPLE
            Get-F1LicensedUsers -SkuMap $skuMap -AllUsers $allUsers

            Returns Id, DisplayName, and UserPrincipalName for every user holding
            an F1 licence.

        .OUTPUTS
            System.Object[] (PSCustomObject with Id, DisplayName, UserPrincipalName)
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$SkuMap,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$AllUsers
    )
    Write-Log "Running Get-F1LicensedUsers" -Level DEBUG

    $f1SkuIds = $SkuMap.Keys | Where-Object { $SkuMap[$_] -in @("SPE_F1", "DESKLESSPACK") }

    if (-not $f1SkuIds) {
        Write-Log -Message "No F1 SKU (SPE_F1 or DESKLESSPACK) found in tenant." -Level WARN
        return @()
    }

    $f1Users = $AllUsers | Where-Object {
        $userSkuIds = $_.AssignedLicenses.SkuId
        ($userSkuIds | Where-Object { $f1SkuIds -contains $_ }).Count -gt 0
    }

    Write-Log -Message "Found $(($f1Users | Measure-Object).Count) user(s) with an F1 licence."

    return @($f1Users | Select-Object Id, DisplayName, UserPrincipalName)
}

function Get-OrphanedMailboxUsers {
    <#
        .SYNOPSIS
            Finds mailboxes belonging to users with no licence that grants a mailbox.

        .DESCRIPTION
            Cross-references the supplied mailbox list against each mailbox
            owner's assigned licences, using the script-scoped
            $mailboxGrantingSkuParts list of SKU-part-number fragments to
            determine whether any assigned licence legitimately grants Exchange
            access. Mailboxes belonging to users with none of those SKUs are
            returned as orphaned. Returns an empty array (never $null) if none
            are found.

        .PARAMETER SkuMap
            Hashtable of SkuId to SkuPartNumber, as returned by Get-TenantSkuMap.

        .PARAMETER AllUsers
            Full user list, as returned by Get-AllTenantUsers.

        .PARAMETER AllMailboxes
            Full mailbox list, as returned by Get-AllTenantMailboxes.

        .EXAMPLE
            Get-OrphanedMailboxUsers -SkuMap $skuMap -AllUsers $allUsers -AllMailboxes $allMailboxes

            Returns Id, DisplayName, and UserPrincipalName for every mailbox owner
            with no licence granting Exchange access.

        .OUTPUTS
            System.Object[] (PSCustomObject with Id, DisplayName, UserPrincipalName)

        .NOTES
            Relies on the script-scoped $mailboxGrantingSkuParts variable. SPE_F1
            and DESKLESSPACK (both F1 variants) are deliberately excluded from
            that list - F1 licences do not grant a mailbox, so an F1-only user is
            correctly treated as orphaned rather than as "licensed enough". Use
            -like matching against SkuPartNumber substrings with care: a prefix
            that's too broad (e.g. a bare "SPE_") can silently re-include an F1
            SKU and mask exactly the users this function needs to catch.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$SkuMap,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$AllUsers,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$AllMailboxes
    )
    Write-Log "Running Get-OrphanedMailboxUsers" -Level DEBUG

    $usersByUpn = @{}
    foreach ($user in $AllUsers) {
        $usersByUpn[$user.UserPrincipalName] = $user
    }

    $orphaned = foreach ($mailbox in $AllMailboxes) {
        $user = $usersByUpn[$mailbox.UserPrincipalName]
        if ($null -eq $user) { continue }

        $hasMailboxLicense = $false
        foreach ($assigned in $user.AssignedLicenses) {
            $skuPartNumber = $SkuMap[$assigned.SkuId]
            if ($mailboxGrantingSkuParts | Where-Object { $skuPartNumber -like "*$_*" }) {
                $hasMailboxLicense = $true
                break
            }
        }

        if (-not $hasMailboxLicense) {
            [PSCustomObject]@{
                Id                = $user.Id
                DisplayName       = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
            }
        }
    }

    Write-Log -Message "Found $(($orphaned | Measure-Object).Count) mailbox(es) with no licence granting Exchange access."

    return @($orphaned)
}

function Get-BlockedUsersState {
    <#
        .SYNOPSIS
            Reads the persistent state file of currently blocked users.

        .DESCRIPTION
            Loads the state file at $stateFilePath, which tracks which users are
            currently OWA-blocked and why, so the script can unblock them later
            if their licence changes. Returns an empty hashtable if the file
            doesn't exist yet (first run) or fails to parse.

        .EXAMPLE
            Get-BlockedUsersState

            Returns a hashtable keyed by UPN, each value containing DisplayName,
            DateBlocked, and Reason.

        .OUTPUTS
            System.Collections.Hashtable

        .NOTES
            Relies on the script-scoped $stateFilePath variable.
    #>
    Write-Log "Running Get-BlockedUsersState" -Level DEBUG
    if (-not (Test-Path $stateFilePath)) {
        return @{}
    }

    Try {
        $data = Import-PowerShellDataFile -Path $stateFilePath -ErrorAction Stop
        return $data
    }
    Catch {
        Write-Log -Message "Failed to read state file, treating as empty: $($_.Exception.Message)" -Level ERROR
        return @{}
    }
}

function Block-UserOWA {
    <#
        .SYNOPSIS
            Disables all Outlook client access (OWA, mobile, Mac, new Outlook) for a single user.

        .DESCRIPTION
            Sets all five OWA-family CAS mailbox parameters (from the
            script-scoped $owaClientParameters list) to $false in a single
            Set-CASMailbox call, logs the outcome, and records a "Blocked" entry
            in the CSV report on success.

        .PARAMETER UserPrincipalName
            UPN of the mailbox to block.

        .PARAMETER DisplayName
            Display name of the user, used in logging and the report.

        .PARAMETER Reason
            Reason the user is being blocked, e.g. "F1 Licence", recorded in the report.

        .EXAMPLE
            Block-UserOWA -UserPrincipalName 'jo@contoso.com' -DisplayName 'Jo Bloggs' -Reason 'F1 Licence'

            Blocks all OWA client access for the user and logs the action.

        .OUTPUTS
            System.Boolean. $true if the block succeeded, $false if it failed.

        .NOTES
            Relies on the script-scoped $owaClientParameters variable. Requires an
            active Exchange Online connection with the Exchange Administrator role.
            Under -WhatIf nothing is changed and $false is returned, so the state
            file is not updated.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory)]
        [string]$DisplayName,
        [Parameter(Mandatory)]
        [string]$Reason
    )
    Write-Log "Running Block-UserOWA" -Level DEBUG

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Block Outlook client access ($Reason)")) {
        return $false
    }

    $setParams = @{ Identity = $UserPrincipalName }
    foreach ($param in $owaClientParameters) {
        $setParams[$param] = $false
    }

    Try {
        Set-CASMailbox @setParams -ErrorAction Stop
        Write-Log -Message "Blocked all OWA client access for $UserPrincipalName ($Reason)."
        Write-Report -UserPrincipalName $UserPrincipalName -DisplayName $DisplayName -Action "Blocked" -Reason $Reason
        return $true
    }
    Catch {
        Write-Log -Message "Failed to block OWA access for $UserPrincipalName : $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Unblock-UserOWA {
    <#
        .SYNOPSIS
            Restores all Outlook client access (OWA, mobile, Mac, new Outlook) for a single user.

        .DESCRIPTION
            Sets all five OWA-family CAS mailbox parameters (from the
            script-scoped $owaClientParameters list) to $true in a single
            Set-CASMailbox call, logs the outcome, and records an "Unblocked"
            entry in the CSV report on success.

        .PARAMETER UserPrincipalName
            UPN of the mailbox to unblock.

        .PARAMETER DisplayName
            Display name of the user, used in logging and the report.

        .EXAMPLE
            Unblock-UserOWA -UserPrincipalName 'jo@contoso.com' -DisplayName 'Jo Bloggs'

            Restores all OWA client access for the user and logs the action.

        .OUTPUTS
            System.Boolean. $true if the unblock succeeded, $false if it failed.

        .NOTES
            Relies on the script-scoped $owaClientParameters variable. Requires an
            active Exchange Online connection with the Exchange Administrator role.
            Under -WhatIf nothing is changed and $false is returned, so the user
            stays in the state file.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory)]
        [string]$DisplayName
    )
    Write-Log "Running Unblock-UserOWA" -Level DEBUG

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, 'Restore Outlook client access')) {
        return $false
    }

    $setParams = @{ Identity = $UserPrincipalName }
    foreach ($param in $owaClientParameters) {
        $setParams[$param] = $true
    }

    Try {
        Set-CASMailbox @setParams -ErrorAction Stop
        Write-Log -Message "Restored all OWA client access for $UserPrincipalName."
        Write-Report -UserPrincipalName $UserPrincipalName -DisplayName $DisplayName -Action "Unblocked" -Reason "Licence no longer requires OWA block"
        return $true
    }
    Catch {
        Write-Log -Message "Failed to restore OWA access for $UserPrincipalName : $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Update-OWABlockStatus {
    <#
        .SYNOPSIS
            Reconciles the current block state against the target list of users who should be blocked.

        .DESCRIPTION
            Blocks any user in the target list not already recorded as blocked,
            and unblocks any currently-blocked user no longer in the target list
            (e.g. because their licence was upgraded). Shows a Write-Progress bar
            for each pass. Users whose unblock fails are retained in the returned
            state so they're retried on the next run rather than silently
            forgotten.

        .PARAMETER UsersToBlock
            Array of user objects (with UserPrincipalName, DisplayName, and
            Reason properties) who should currently be blocked, as built from
            Get-F1LicensedUsers and Get-OrphanedMailboxUsers.

        .PARAMETER CurrentState
            Hashtable of currently blocked users, as returned by
            Get-BlockedUsersState.

        .EXAMPLE
            Update-OWABlockStatus -UsersToBlock $targetUsers -CurrentState $currentState

            Blocks/unblocks users as needed and returns the updated state hashtable.

        .OUTPUTS
            System.Collections.Hashtable. The updated state to persist via
            Save-BlockedUsersState.

        .NOTES
            Filters $null entries from $UsersToBlock defensively, since a filtered
            pipeline producing zero results assigns $null rather than an empty
            array in PowerShell, which would otherwise throw inside
            $CurrentState.ContainsKey().
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$UsersToBlock,
        [Parameter(Mandatory)]
        [hashtable]$CurrentState
    )
    Write-Log "Running Update-OWABlockStatus" -Level DEBUG

    $UsersToBlock = @($UsersToBlock | Where-Object { $null -ne $_ })

    $newState = @{}

    $blockCount = ($UsersToBlock | Measure-Object).Count
    $blockIndex = 0

    if ($blockCount -gt 0) {
        foreach ($user in $UsersToBlock) {
            $blockIndex++
            Write-Progress -Id 1 -Activity "Checking OWA block list" -Status "$($user.UserPrincipalName) ($blockIndex of $blockCount)" -PercentComplete (($blockIndex / $blockCount) * 100)

            $upn = $user.UserPrincipalName

            if ($CurrentState.ContainsKey($upn)) {
                $newState[$upn] = $CurrentState[$upn]
                continue
            }

            $blocked = Block-UserOWA -UserPrincipalName $upn -DisplayName $user.DisplayName -Reason $user.Reason
            if ($blocked) {
                $newState[$upn] = @{
                    DisplayName = $user.DisplayName
                    DateBlocked = (Get-Date -Format "yyyy-MM-dd")
                    Reason      = $user.Reason
                }
            }
        }

        Write-Progress -Id 1 -Activity "Checking OWA block list" -Completed
    }

    $unblockCandidates = @($CurrentState.Keys | Where-Object {
        $upn = $_
        -not ($UsersToBlock | Where-Object { $_.UserPrincipalName -eq $upn })
    })

    $unblockCount = $unblockCandidates.Count
    $unblockIndex = 0

    if ($unblockCount -gt 0) {
        foreach ($upn in $unblockCandidates) {
            $unblockIndex++
            Write-Progress -Id 2 -Activity "Restoring OWA access" -Status "$upn ($unblockIndex of $unblockCount)" -PercentComplete (($unblockIndex / $unblockCount) * 100)

            $unblocked = Unblock-UserOWA -UserPrincipalName $upn -DisplayName $CurrentState[$upn].DisplayName
            if (-not $unblocked) {
                $newState[$upn] = $CurrentState[$upn]
            }
        }

        Write-Progress -Id 2 -Activity "Restoring OWA access" -Completed
    }

    return $newState
}

function Save-BlockedUsersState {
    <#
        .SYNOPSIS
            Writes the current block state to the persistent state file.

        .DESCRIPTION
            Serialises the supplied state hashtable to a human-readable .psd1
            file at $stateFilePath, escaping single quotes in DisplayName and
            Reason values so names like "O'Brien" don't corrupt the file's
            PowerShell syntax.

        .PARAMETER State
            Hashtable of currently blocked users to persist, keyed by UPN.

        .EXAMPLE
            Save-BlockedUsersState -State $newState

            Writes the state file to disk.

        .OUTPUTS
            None. Writes the state file to disk.

        .NOTES
            Relies on the script-scoped $stateFilePath variable.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$State
    )
    Write-Log "Running Save-BlockedUsersState" -Level DEBUG

    $stateDir = Split-Path -Path $stateFilePath -Parent
    if (-not (Test-Path $stateDir)) {
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    }

    $lines = foreach ($key in $State.Keys) {
        $user = $State[$key]
        $safeDisplayName = $user.DisplayName -replace "'", "''"
        $safeReason = $user.Reason -replace "'", "''"
        "    '$key' = @{ DisplayName = '$safeDisplayName'; DateBlocked = '$($user.DateBlocked)'; Reason = '$safeReason' }"
    }

    $content = "@{`n$($lines -join "`n")`n}"

    Try {
        Set-Content -Path $stateFilePath -Value $content -Encoding UTF8 -ErrorAction Stop
        Write-Log -Message "State file updated: $($State.Keys.Count) user(s) currently blocked."
    }
    Catch {
        Write-Log -Message "Failed to write state file: $($_.Exception.Message)" -Level ERROR
    }
}

function Copy-LegacyStateFile {
    <#
        .SYNOPSIS
            Copies the pre-1.2.0 state file to the current location on first run.

        .DESCRIPTION
            Before 1.2.0 the state file lived at a fixed path under
            C:\Pickering-Cloud. Without it, previously blocked users who no longer
            need blocking would never be unblocked. The old file is copied, not
            moved, so it is left in place as a backup.

        .OUTPUTS
            None.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ((Test-Path -LiteralPath $stateFilePath) -or -not (Test-Path -LiteralPath $legacyStateFilePath)) {
        return
    }

    if ($PSCmdlet.ShouldProcess($stateFilePath, "Copy legacy state file from $legacyStateFilePath")) {
        Copy-Item -LiteralPath $legacyStateFilePath -Destination $stateFilePath -ErrorAction Stop
        Write-Log -Message "Copied the state file from its pre-1.2.0 location ($legacyStateFilePath) to $stateFilePath." -Level WARN
    }
}

##################################################
# Pre-Requisite Checks
##################################################

try {
    Initialize-OutputFolder

    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Applications",
        "ExchangeOnlineManagement"
    )

    Test-RequiredModules -Modules $requiredModules
    Test-Config
    Connect-TenantMG
    Connect-TenantEXO

    ##################################################
    # Script
    ##################################################

    $skuMap = Get-TenantSkuMap
    $allUsers = Get-AllTenantUsers
    $allMailboxes = Get-AllTenantMailboxes

    $f1Users = @(Get-F1LicensedUsers -SkuMap $skuMap -AllUsers $allUsers | Select-Object *, @{Name="Reason"; Expression={"F1 Licence"}})
    $orphanedUsers = @(Get-OrphanedMailboxUsers -SkuMap $skuMap -AllUsers $allUsers -AllMailboxes $allMailboxes | Select-Object *, @{Name="Reason"; Expression={"No qualifying mailbox licence"}})
    $targetUsers = $f1Users + $orphanedUsers

    Copy-LegacyStateFile
    $currentState = Get-BlockedUsersState
    $newState = Update-OWABlockStatus -UsersToBlock $targetUsers -CurrentState $currentState
    Save-BlockedUsersState -State $newState

    Disconnect-ExchangeOnline -Confirm:$false
    Disconnect-MgGraph

    Remove-ExpiredOutput -Folder $ReportPath -OlderThanDays $RetentionDays
}
catch {
    Exit-WithError "Unhandled error: $($_.Exception.Message)"
}
finally {
    # Runs on every exit path, including Exit-WithError.
    try {
        Invoke-UpdateCheckAndTelemetry
    }
    catch {
        Write-Log -Message "Update check or telemetry error: $($_.Exception.Message)" -Level Debug
    }
}