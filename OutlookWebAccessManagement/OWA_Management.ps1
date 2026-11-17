<#
    .SYNOPSIS
        Script to block Outlook Web Access for users with a F1 license

    .DESCRIPTION
        Checks against configured Entra environment to retrieve license(s) and will disable OWA where required to avoid invalidating license

    .PARAMETER Setup
        Runs interactive service principal creation if one is not already configured. Requires Application Administrator (or Global Administrator) and Privileged Role Administrator rights in Entra. Not needed on normal unattended runs once the service principal exists.

    .PARAMETER DisableUpdateCheck
        Skips the check for a newer version. No network request is made for this purpose.

    .PARAMETER DisableTelemetry
        Stops anonymous usage telemetry being sent. The update check still runs unless -DisableUpdateCheck is also used. Telemetry can also be disabled for every tool at once by setting the environment variable PICKERINGCLOUD_NOTELEMETRY to 1, for example via Group Policy.

    .EXAMPLE
        .\Manage-OWA.ps1

        Runs the script normally: connects using the existing service principal, queries the tenant for F1-licensed users and mailboxes without a qualifying licence, blocks/unblocks Outlook client access accordingly, and updates the report and state files.

    .EXAMPLE
        .\Manage-OWA.ps1 -Setup

        Runs interactive service principal setup first (if not already configured), then continues into a normal run.

    .OUTPUTS
        None. Writes progress to the console and to the log file at C:\Pickering-Cloud\Logs\OWAManagement, appends blocked/unblocked actions to a dated CSV report at C:\Pickering-Cloud\Reports\OWAManagement, and maintains a persistent state file (BlockedUsers.psd1) tracking currently blocked users.

    .NOTES
        Author: Bradley Pickering
        Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Applications, ExchangeOnlineManagement modules.
        Requires: Exchange Administrator directory role assigned to the service principal, and admin consent granted on its Graph application permissions, before the first unattended run.
        Update check and telemetry: after the run, the script reads a static version file from pickering.cloud and tells you if a newer version exists. It never downloads or installs anything. Unless disabled, it also sends anonymous usage data (tool, version, OS, PowerShell version, timezone, run mode). No tenant, user, mailbox or licence details are sent. See TELEMETRY.md in the repository root for the full list.
#>

##################################################
# Script Parameters
##################################################
[CmdletBinding()]
param(
    [switch]$Setup,
    [switch]$DisableUpdateCheck,
    [switch]$DisableTelemetry
)

##################################################
# Variables
##################################################
$configPath = ".\config.psd1"
$config = Import-PowerShellDataFile -Path $configPath -ErrorAction SilentlyContinue

$tenantID = $config.TenantId
$applicationID = $config.ClientId
$applicationThumbprint = $config.clientThumbprint

$date = Get-Date -Format "yyyyMMdd"
$logPath = "C:\Pickering-Cloud\Logs\OWAManagement\$($date).log"
$reportPath = "C:\Pickering-Cloud\Reports\OWAManagement\$($date).csv"
$stateFilePath = "C:\Pickering-Cloud\Reports\OWAManagement\BlockedUsers.psd1"

$ScriptName = 'OutlookWebAccessManagement'
$ScriptVersion = '1.1.0'
$UpdateCheckUrl = 'https://pickering.cloud/tools/versions.json'
$TelemetryUrl = 'https://pickering.cloud/api/telemetry'
$NetworkUserAgent = 'PickeringCloud-Toolkit'

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
# Logging/Reporting
##################################################

function Configure-LogPath {
    <#
        .SYNOPSIS
            Ensures the log directory exists.

        .DESCRIPTION
            Checks whether the parent directory of $logPath exists, creating it if
            necessary. Called internally by Write-Log before every write, so the
            log directory is created on demand rather than requiring manual setup.

        .EXAMPLE
            Configure-LogPath

            Returns $true if the log directory exists or was created successfully,
            $false if directory creation failed.

        .OUTPUTS
            System.Boolean

        .NOTES
            Relies on the script-scoped $logPath variable rather than taking a
            parameter, since it's only ever called internally by Write-Log.
    #>
    $logDir = Split-Path -Path $logPath -Parent

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
            Appends an entry to the dated log file at $logPath and echoes it to
            the console via Write-Host. CRITICAL-level messages exit the script
            with code 1 after being logged, regardless of whether the log file
            itself could be written, so a broken logging path can never silently
            swallow a fatal error.

        .PARAMETER Message
            The text to log.

        .PARAMETER Level
            Severity of the entry. One of INFO, WARN, ERROR, CRITICAL. Defaults to
            INFO. CRITICAL causes the script to exit after logging.

        .EXAMPLE
            Write-Log -Message "Connected to tenant" -Level INFO

            Logs an informational message.

        .EXAMPLE
            Write-Log -Message "Service principal not configured." -Level CRITICAL

            Logs a critical error and exits the script with code 1.

        .OUTPUTS
            None. Writes to the log file and console; exits the script for
            CRITICAL-level messages.

        .NOTES
            Depends on the script-scoped $logPath variable via Configure-LogPath.
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
<<<<<<< HEAD
        $time = Get-Date -Format "HH:mm:ss.zzz"
=======
        $time = Get-Date -Format "HH:mm:ss.fff"
>>>>>>> origin/main
        $entry = "$time | $prefix | $Message"
        Add-Content -Value $entry -Path $logPath
        Write-Host $entry
    }
    else {
        Write-Host "$prefix | $Message (log file unavailable)" -ForegroundColor Red
    }

    if ($Level -eq "CRITICAL") {
        exit 1
    }
}

function Configure-ReportPath {
    <#
        .SYNOPSIS
            Ensures the report directory exists.

        .DESCRIPTION
            Checks whether the parent directory of $reportPath exists, creating it
            if necessary. Called internally by Write-Report before every write.
            Directory creation failure is escalated via Write-Log -Level CRITICAL,
            which halts the script, since a report that can never be written
            undermines the auditing requirement the script exists to satisfy.

        .EXAMPLE
            Configure-ReportPath

            Returns $true if the report directory exists or was created
            successfully. The script exits before returning if creation fails.

        .OUTPUTS
            System.Boolean

        .NOTES
            Relies on the script-scoped $reportPath variable rather than taking a
            parameter, since it's only ever called internally by Write-Report.
    #>
    Write-Log "Running Configure-ReportPath" -Level DEBUG
    $reportDir = Split-Path -Path $reportPath -Parent

    if (-not (Test-Path $reportDir)) {
        Try {
            New-Item -ItemType Directory -Path $reportDir -Force -ErrorAction Stop | Out-Null
        }
        Catch {
            Write-Log "Failed creating log path: $reportDir" -Level CRITICAL
        }
    }

    return $true
}

function Write-Report {
    <#
        .SYNOPSIS
            Appends a Blocked/Unblocked audit entry to the dated CSV report.

        .DESCRIPTION
            Records a single OWA block or unblock action, with timestamp, user
            details, and reason, to the CSV report at $reportPath. This is the
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
            None. Appends a row to the CSV report file at $reportPath.

        .NOTES
            Called internally by Block-UserOWA and Unblock-UserOWA. Relies on the
            script-scoped $reportPath variable.
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

    if (Configure-ReportPath) {
        $entry = [PSCustomObject]@{
            Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            UserPrincipalName = $UserPrincipalName
            DisplayName       = $DisplayName
            Action            = $Action
            Reason            = $Reason
        }

        Try {
            $entry | Export-Csv -Path $reportPath -Append -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Failed to write report entry for $UserPrincipalName : $($_.Exception.Message)" -Level ERROR
        }
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
    Write-Log "Running Update-Config" -Level DEBUG
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientThumbprint
    )

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
            Write-Log -Message "Service principal not configured. Re-run with -Setup to provision it interactively." -Level CRITICAL
        }

        $spDetails = New-OWAServicePrincipal
        if ($null -eq $spDetails) {
            Write-Log -Message "Service principal setup did not complete - aborting." -Level CRITICAL
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
        Write-Log -Message "Failed to retrieve tenant initial domain: $($_.Exception.Message)" -Level CRITICAL
    }

    Try {
        Connect-ExchangeOnline -AppId $applicationID -CertificateThumbprint $applicationThumbprint -Organization $initialDomain -ShowBanner:$false -ErrorAction Stop
        Write-Log -Message "Connected to Exchange Online for tenant: $initialDomain."
    }
    Catch {
        Write-Log -Message "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level ERROR
        Write-Log -Message "If this service principal was created recently, this can be caused by Entra role and certificate propagation delay - wait a few minutes and try again before investigating further." -Level CRITICAL
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
        Write-Log -Message "No certificate thumbprint provided - please update $configPath." -Level CRITICAL
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
        Write-Log -Message "Failed to retrieve subscribed SKUs: $($_.Exception.Message)" -Level CRITICAL
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
        Write-Log -Message "Failed to retrieve user list: $($_.Exception.Message)" -Level CRITICAL
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
        Write-Log -Message "Failed to retrieve mailboxes from Exchange Online: $($_.Exception.Message)" -Level CRITICAL
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
        [array]$AllUsers,
        [Parameter(Mandatory)]
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
    #>
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory)]
        [string]$DisplayName,
        [Parameter(Mandatory)]
        [string]$Reason
    )
    Write-Log "Running Block-UserOWA" -Level DEBUG

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
    #>
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory)]
        [string]$DisplayName
    )
    Write-Log "Running Unblock-UserOWA" -Level DEBUG

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

function Get-RunMode {
    <#
        .SYNOPSIS
            Reports whether the script is running interactively or unattended.

        .DESCRIPTION
            Returns 'unattended' if the session is not user-interactive, was started
            with -NonInteractive, or has redirected input (for example a Scheduled
            Task). Otherwise returns 'interactive'. The PowerShell ISE and the Visual
            Studio Code terminal are always treated as interactive.

        .EXAMPLE
            Get-RunMode

            Returns 'interactive' when run from a normal console window.

        .OUTPUTS
            System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not [Environment]::UserInteractive) {
        return 'unattended'
    }

    if (@([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-NonI' }).Count -gt 0) {
        return 'unattended'
    }

    if ($Host.Name -like '*ISE*' -or $Host.Name -like '*Visual Studio Code*') {
        return 'interactive'
    }

    try {
        if ([Console]::IsInputRedirected) {
            return 'unattended'
        }
    }
    catch {
        return 'unattended'
    }

    return 'interactive'
}

function Limit-Text {
    <#
        .SYNOPSIS
            Removes control characters from a string and truncates it to a maximum length.

        .DESCRIPTION
            Used to keep telemetry values within the lengths the server accepts.

        .PARAMETER Text
            The text to clean.

        .PARAMETER Max
            The maximum number of characters to keep.

        .EXAMPLE
            Limit-Text -Text 'GMT Standard Time' -Max 64

            Returns the text unchanged, as it is within the limit.

        .OUTPUTS
            System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text,
        [Parameter(Mandatory)]
        [int]$Max
    )

    $clean = ($Text -replace '[\x00-\x1F\x7F]', '').Trim()
    if ($clean.Length -gt $Max) {
        $clean = $clean.Substring(0, $Max)
    }
    return $clean
}

function Get-LatestToolVersion {
    <#
        .SYNOPSIS
            Reads the latest published version of this tool from the static version file.

        .DESCRIPTION
            Makes a plain GET request with a generic User-Agent and sends no data.
            Returns $null if the check fails for any reason, including no network
            access.

        .EXAMPLE
            Get-LatestToolVersion

            Returns an object with Version, Released, Url and Newer properties, or $null.

        .OUTPUTS
            System.Management.Automation.PSCustomObject, or $null.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $response = Invoke-RestMethod -Uri $UpdateCheckUrl -Method Get -TimeoutSec 5 -UserAgent $NetworkUserAgent -ErrorAction Stop
        $entry = $response.tools.$ScriptName

        if (-not $entry) {
            Write-Log -Message "Update check: $ScriptName is not listed in the version file." -Level INFO
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
        Write-Log -Message "Update check failed: $($_.Exception.Message)" -Level INFO
        return $null
    }
}

function Show-UpdateNotice {
    <#
        .SYNOPSIS
            Tells the user a newer version exists and, in an interactive session only, offers to open the release page.

        .DESCRIPTION
            Always writes the notice to the log. In an interactive session, also asks
            whether to open the release page. Never prompts in an unattended session.
            Only github.com addresses are opened.

        .PARAMETER Latest
            The object returned by Get-LatestToolVersion.

        .EXAMPLE
            Show-UpdateNotice -Latest $latest

            Reports that a newer version is available.

        .OUTPUTS
            None.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [pscustomobject]$Latest
    )

    Write-Log -Message "Update available: $ScriptName $($Latest.Version) (you have $ScriptVersion). Release page: $($Latest.Url)" -Level INFO

    if ((Get-RunMode) -ne 'interactive') {
        return
    }

    $answer = Read-Host 'Open the release page in your browser now? (y/N)'

    if ($answer.Trim().ToLower() -in 'y', 'yes') {
        # Only open GitHub links, in case the version file were ever tampered with.
        if ($Latest.Url -match '^https://github\.com/') {
            Start-Process -FilePath $Latest.Url
        }
        else {
            Write-Log -Message "Not opening $($Latest.Url): it is not a github.com address." -Level WARN
        }
    }
}

function Send-ToolTelemetry {
    <#
        .SYNOPSIS
            Sends anonymous usage telemetry.

        .DESCRIPTION
            Sends tool name, tool version, OS caption and build, PowerShell version and
            edition, timezone ID and run mode. The server adds the country from the
            request and a daily salted hash of the IP address. No tenant, user, mailbox
            or licence details are ever included. See TELEMETRY.md in the repository
            root. Run the script with -Verbose to see the exact payload.

        .EXAMPLE
            Send-ToolTelemetry

            Sends the anonymous usage record for this run.

        .OUTPUTS
            None.
    #>
    [CmdletBinding(SupportsShouldProcess)]
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

        $payload = [ordered]@{
            tool      = $ScriptName
            version   = $ScriptVersion
            os        = Limit-Text -Text $osCaption -Max 64
            osBuild   = Limit-Text -Text $osBuild -Max 32
            psVersion = Limit-Text -Text $PSVersionTable.PSVersion.ToString() -Max 32
            psEdition = if ($PSVersionTable.PSEdition -eq 'Core') { 'Core' } else { 'Desktop' }
            timezone  = Limit-Text -Text ([TimeZoneInfo]::Local.Id) -Max 64
            runMode   = Get-RunMode
        }

        $json = $payload | ConvertTo-Json -Compress
        Write-Verbose "Telemetry payload: $json"

        if ($PSCmdlet.ShouldProcess($TelemetryUrl, 'Send anonymous usage telemetry')) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $bytes = [Text.Encoding]::UTF8.GetBytes($json)
            Invoke-RestMethod -Uri $TelemetryUrl -Method Post -Body $bytes -ContentType 'application/json' -TimeoutSec 5 -UserAgent $NetworkUserAgent -ErrorAction Stop | Out-Null
            Write-Verbose 'Telemetry sent.'
        }
    }
    catch {
        Write-Log -Message "Telemetry not sent: $($_.Exception.Message)" -Level INFO
    }
}

function Invoke-UpdateCheckAndTelemetry {
    <#
        .SYNOPSIS
            Runs the optional update check and telemetry, honouring the opt-out switches.

        .DESCRIPTION
            Skips the update check if -DisableUpdateCheck was used. Skips telemetry if
            -DisableTelemetry was used or the environment variable
            PICKERINGCLOUD_NOTELEMETRY is 1 or true. The two are independent. Neither
            can affect the result of the script.

        .EXAMPLE
            Invoke-UpdateCheckAndTelemetry

            Checks for a newer version and sends telemetry, unless disabled.

        .OUTPUTS
            None.
    #>
    [CmdletBinding()]
    param()

    if ($DisableUpdateCheck) {
        Write-Verbose 'Update check disabled.'
    }
    else {
        $latest = Get-LatestToolVersion
        if ($latest -and $latest.Newer) {
            Show-UpdateNotice -Latest $latest
        }
        elseif ($latest) {
            Write-Verbose "Update check: $ScriptName $ScriptVersion is the latest version."
        }
    }

    $telemetryOff = $DisableTelemetry -or ($env:PICKERINGCLOUD_NOTELEMETRY -in '1', 'true')
    if ($telemetryOff) {
        Write-Verbose 'Telemetry disabled.'
    }
    else {
        Write-Log -Message 'Anonymous usage telemetry is on. Disable it with -DisableTelemetry or PICKERINGCLOUD_NOTELEMETRY=1. See TELEMETRY.md in the repository root.' -Level INFO
        Send-ToolTelemetry
    }
}

##################################################
# Pre-Requisite Checks
##################################################

try {
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

    $currentState = Get-BlockedUsersState
    $newState = Update-OWABlockStatus -UsersToBlock $targetUsers -CurrentState $currentState
    Save-BlockedUsersState -State $newState

    Disconnect-ExchangeOnline -Confirm:$false
    Disconnect-MgGraph
}
finally {
    # Runs on every exit path, including Write-Log -Level CRITICAL, which exits the script.
    try {
        Invoke-UpdateCheckAndTelemetry
    }
    catch {
        Write-Log -Message "Update check or telemetry error: $($_.Exception.Message)" -Level INFO
    }
}