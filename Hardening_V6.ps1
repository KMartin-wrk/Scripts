#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Security Hardening Script based on CIS Benchmarks and Microsoft Security Baselines
.DESCRIPTION
    Applies industry-recognized hardening steps for Windows Server 2016-2025 and Windows 10/11
.NOTES
    Must be run as Administrator
    Creates backup of registry before changes
    Comprehensive logging to .log and .csv files
#>

# Global variables for logging
$script:LogPath = ""
$script:CsvPath = ""
$script:Hostname = $env:COMPUTERNAME
$script:OSVersion = ""
$script:TargetVersion = ""

function Initialize-Logging {
    param (
        [string]$TargetOS
    )
    
    $script:TargetVersion = $TargetOS
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logDir = "C:\SecurityHardening"
    
    # Create log directory if it doesn't exist
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    # Set log file paths
    $script:LogPath = Join-Path $logDir "Hardening_$timestamp.log"
    $script:CsvPath = Join-Path $logDir "Hardening_Evidence.csv"
    
    # Get OS information
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $script:OSVersion = "$($osInfo.Caption) (Build $($osInfo.BuildNumber))"
    
    # Create CSV header if file doesn't exist
    if (-not (Test-Path $script:CsvPath)) {
        $csvHeader = "Timestamp_UTC,Hostname,OS_Version,Target_Version,Action,Result,ErrorMessage,Original_Value"
        $csvHeader | Out-File -FilePath $script:CsvPath -Encoding UTF8
    }
    
    # Write initial log entry
    Write-Log -Action "Script Started" -Result "Success" -Message "Initializing security hardening for $TargetOS"
    Write-Host "[*] Logging initialized:" -ForegroundColor Cyan
    Write-Host "    Log file: $script:LogPath" -ForegroundColor White
    Write-Host "    CSV file: $script:CsvPath" -ForegroundColor White
}

function Write-Log {
    param (
        [string]$Action,
        [string]$Result,
        [string]$Message = "",
        [string]$OriginalValue = ""
    )
    
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
    
    # Write to log file
    $logEntry = "[$timestamp] [$Result] $Action"
    if ($Message) {
        $logEntry += " - $Message"
    }
    if ($OriginalValue) {
        $logEntry += " (Original Value: $OriginalValue)"
    }
    $logEntry | Out-File -FilePath $script:LogPath -Append -Encoding UTF8
    
    # Write to CSV (append-safe with proper escaping)
    $csvMessage = $Message -replace '"', '""'  # Escape quotes for CSV
    $csvOriginalValue = $OriginalValue -replace '"', '""'  # Escape quotes for CSV
    $csvLine = "`"$timestamp`",`"$script:Hostname`",`"$script:OSVersion`",`"$script:TargetVersion`",`"$Action`",`"$Result`",`"$csvMessage`",`"$csvOriginalValue`""
    $csvLine | Out-File -FilePath $script:CsvPath -Append -Encoding UTF8
}

function Get-OriginalRegistryValue {
    param (
        [string]$Path,
        [string]$Name
    )
    
    try {
        if (Test-Path $Path) {
            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($item) {
                return $item.$Name
            }
        }
        return "(Not Set)"
    }
    catch {
        return "(Not Set)"
    }
}

function Show-Menu {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Windows Security Hardening Tool" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Select your Windows version:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Windows Server 2016"
    Write-Host "2. Windows Server 2019"
    Write-Host "3. Windows Server 2022"
    Write-Host "4. Windows Server 2025"
    Write-Host "5. Windows 10"
    Write-Host "6. Windows 11"
    Write-Host "Q. Quit"
    Write-Host ""
}

function Backup-Registry {
    Write-Host "[*] Creating registry backup..." -ForegroundColor Yellow
    try {
        $backupPath = "C:\SecurityHardening\OriginalRegistryBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        $result = reg export HKLM $backupPath /y 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Registry backed up to: $backupPath" -ForegroundColor Green
            Write-Log -Action "Registry Backup" -Result "Success" -Message "Backup created at $backupPath"
        } else {
            throw "Registry export failed with exit code $LASTEXITCODE"
        }
    }
    catch {
        Write-Host "[-] Registry backup failed: $_" -ForegroundColor Red
        Write-Log -Action "Registry Backup" -Result "Failed" -Message $_.Exception.Message
    }
}

function New-RegistryBackup {
    Write-Host "`n[*] Creating post-hardening registry backup..." -ForegroundColor Yellow
    try {
        $backupPath = "C:\SecurityHardening\NewRegistryBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        $result = reg export HKLM $backupPath /y 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Post-hardening registry backed up to: $backupPath" -ForegroundColor Green
            Write-Log -Action "Post-Hardening Registry Backup" -Result "Success" -Message "Backup created at $backupPath"
        } else {
            throw "Registry export failed with exit code $LASTEXITCODE"
        }
    }
    catch {
        Write-Host "[-] Post-hardening registry backup failed: $_" -ForegroundColor Red
        Write-Log -Action "Post-Hardening Registry Backup" -Result "Failed" -Message $_.Exception.Message
    }
}


function Set-AccountPolicies {
    Write-Host "`n[*] Configuring Account Policies..." -ForegroundColor Cyan
    
    try {
        # Password Policy
        $result = net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:24 2>&1
        Write-Log -Action "Password Policy Configuration" -Result "Success" -Message "Min length: 14, Max age: 60, Min age: 1, History: 24"
        
        # Account Lockout Policy
        $result = net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 2>&1
        Write-Log -Action "Account Lockout Policy" -Result "Success" -Message "Threshold: 5, Duration: 15 min, Window: 15 min"
        
        Write-Host "[+] Account policies configured" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Failed to configure account policies: $_" -ForegroundColor Red
        Write-Log -Action "Account Policies Configuration" -Result "Failed" -Message $_.Exception.Message
    }
}

function Set-AuditPolicies {
    Write-Host "`n[*] Configuring Audit Policies..." -ForegroundColor Cyan
    
    $auditSettings = @(
        @{Category="Account Logon"; Description="Account Logon Events"},
        @{Category="Account Management"; Description="Account Management Events"},
        @{Category="Logon/Logoff"; Description="Logon/Logoff Events"},
        @{Category="Policy Change"; Description="Policy Change Events"},
        @{Category="Privilege Use"; Description="Privilege Use Events"},
        @{Category="System"; Description="System Events"},
        @{Category="Detailed Tracking"; Description="Detailed Tracking Events"}
    )
    
    foreach ($setting in $auditSettings) {
        try {
            $result = Invoke-Expression "auditpol /set /category:`"$($setting.Category)`" /success:enable /failure:enable" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log -Action "Audit Policy: $($setting.Description)" -Result "Success" -Message "Success and Failure auditing enabled"
            } else {
                throw "auditpol returned exit code $LASTEXITCODE"
            }
        }
        catch {
            Write-Log -Action "Audit Policy: $($setting.Description)" -Result "Failed" -Message $_.Exception.Message
        }
    }
    
    Write-Host "[+] Audit policies configured" -ForegroundColor Green
}

function Set-TLSHardening {
    param (
        [bool]$DisableOldTLS
    )
    
    if (-not $DisableOldTLS) {
        Write-Host "`n[!] Skipping TLS/SSL hardening (user declined)" -ForegroundColor Yellow
        Write-Log -Action "TLS/SSL Hardening" -Result "Skipped" -Message "User declined TLS/SSL hardening"
        return
    }
    
    Write-Host "`n[*] Applying TLS/SSL Hardening..." -ForegroundColor Cyan
    Write-Log -Action "TLS/SSL Hardening" -Result "Started" -Message "Beginning TLS/SSL configuration"
    
    $tlsSettings = @(
        # Disable TLS 1.0
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable TLS 1.0 Server"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"; Name="DisabledByDefault"; Value=1; Type="DWORD"; Description="TLS 1.0 Server Disabled by Default"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable TLS 1.0 Client"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"; Name="DisabledByDefault"; Value=1; Type="DWORD"; Description="TLS 1.0 Client Disabled by Default"},
        
        # Disable TLS 1.1
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable TLS 1.1 Server"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"; Name="DisabledByDefault"; Value=1; Type="DWORD"; Description="TLS 1.1 Server Disabled by Default"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable TLS 1.1 Client"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"; Name="DisabledByDefault"; Value=1; Type="DWORD"; Description="TLS 1.1 Client Disabled by Default"},
        
        # Disable SSL 2.0
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable SSL 2.0 Server"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable SSL 2.0 Client"},
        
        # Disable SSL 3.0
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable SSL 3.0 Server"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable SSL 3.0 Client"},
        
        # Enable TLS 1.2
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"; Name="Enabled"; Value=1; Type="DWORD"; Description="Enable TLS 1.2 Server"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"; Name="DisabledByDefault"; Value=0; Type="DWORD"; Description="TLS 1.2 Server Enabled by Default"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"; Name="Enabled"; Value=1; Type="DWORD"; Description="Enable TLS 1.2 Client"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"; Name="DisabledByDefault"; Value=0; Type="DWORD"; Description="TLS 1.2 Client Enabled by Default"},
        
        # Enable TLS 1.3
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"; Name="Enabled"; Value=1; Type="DWORD"; Description="Enable TLS 1.3 Server"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"; Name="DisabledByDefault"; Value=0; Type="DWORD"; Description="TLS 1.3 Server Enabled by Default"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"; Name="Enabled"; Value=1; Type="DWORD"; Description="Enable TLS 1.3 Client"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"; Name="DisabledByDefault"; Value=0; Type="DWORD"; Description="TLS 1.3 Client Enabled by Default"},
        
        # Disable weak ciphers
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable DES 56/56"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable RC2 40/128"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable RC2 56/128"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable RC4 40/128"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable RC4 56/128"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable RC4 64/128"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable RC4 128/128"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable Triple DES 168"},
        
        # Set cipher suite order
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"; Name="Functions"; Value="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"; Type="String"; Description="Set Strong Cipher Suite Order"}
    )
    
    foreach ($setting in $tlsSettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            $originalValue = Get-OriginalRegistryValue -Path $setting.Path -Name $setting.Name
            New-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force | Out-Null
            Write-Log -Action $setting.Description -Result "Success" -Message "Path: $($setting.Path), Value: $($setting.Value)" -OriginalValue $originalValue
        }
        catch {
            Write-Host "[-] Failed to set $($setting.Description): $_" -ForegroundColor Red
            Write-Log -Action $setting.Description -Result "Failed" -Message $_.Exception.Message
        }
    }
    
    Write-Host "[+] TLS/SSL hardening applied" -ForegroundColor Green
    Write-Host "[!] TLS 1.0, TLS 1.1, SSL 2.0, SSL 3.0 DISABLED" -ForegroundColor Yellow
    Write-Host "[!] Weak ciphers (RC4, DES, 3DES) DISABLED" -ForegroundColor Yellow
    Write-Host "[+] TLS 1.2 and TLS 1.3 ENABLED" -ForegroundColor Green
}

function Set-RegistryHardening {
    param (
        [bool]$DisableRDP
    )
    
    Write-Host "`n[*] Applying Registry Security Settings..." -ForegroundColor Cyan
    
    $regSettings = @(
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Value=0; Type="DWORD"; Description="Disable SMBv1"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"; Value=1; Type="DWORD"; Description="Enable LSA Protection (RunAsPPL)"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name="UseLogonCredential"; Value=0; Type="DWORD"; Description="Disable WDigest credential caching"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableMulticast"; Value=0; Type="DWORD"; Description="Disable LLMNR"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NodeType"; Value=2; Type="DWORD"; Description="Disable NetBIOS"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"; Value=1; Type="DWORD"; Description="Enable Virtualization Based Security"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name="RequirePlatformSecurityFeatures"; Value=1; Type="DWORD"; Description="Require Platform Security Features"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LsaCfgFlags"; Value=1; Type="DWORD"; Description="Enable Credential Guard"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Value=1; Type="DWORD"; Description="Restrict Anonymous Access"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Value=1; Type="DWORD"; Description="Restrict Anonymous SAM Access"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictRemoteSAM"; Value="O:BAG:BAD:(A;;RC;;;BA)"; Type="String"; Description="Disable Anonymous Share Enumeration"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Value=255; Type="DWORD"; Description="Disable AutoRun for all drives"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoAutoplayfornonVolume"; Value=1; Type="DWORD"; Description="Disable Autoplay for non-volume devices"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableRealtimeMonitoring"; Value=0; Type="DWORD"; Description="Enable Windows Defender Real-time Protection"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="PUAProtection"; Value=1; Type="DWORD"; Description="Enable PUA Protection"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="SecurityLayer"; Value=2; Type="DWORD"; Description="Set RDP Security Layer to TLS"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="UserAuthentication"; Value=1; Type="DWORD"; Description="Require Network Level Authentication for RDP"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name="fAllowToGetHelp"; Value=0; Type="DWORD"; Description="Disable Remote Assistance"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Value=5; Type="DWORD"; Description="Enable NTLMv2 only"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Value=1; Type="DWORD"; Description="Require SMB Signing (Client)"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableSecuritySignature"; Value=1; Type="DWORD"; Description="Enable SMB Signing (Client)"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RequireSecuritySignature"; Value=1; Type="DWORD"; Description="Require SMB Signing (Server)"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="EnableSecuritySignature"; Value=1; Type="DWORD"; Description="Enable SMB Signing (Server)"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AllowInsecureGuestAuth"; Value=0; Type="DWORD"; Description="Disable Insecure Guest Logons"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Value=2; Type="DWORD"; Description="Disable IP Source Routing (IPv4)"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name="DisableIPSourceRouting"; Value=2; Type="DWORD"; Description="Disable IP Source Routing (IPv6)"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"; Name="Enabled"; Value=0; Type="DWORD"; Description="Disable Windows Script Host"},
        @{Path="HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine"; Name="PowerShellVersion"; Value=0; Type="DWORD"; Description="Disable PowerShell v2"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Value=1; Type="DWORD"; Description="Enable UAC"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Value=0; Type="DWORD"; Description="UAC: Auto-deny elevation requests"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="PromptOnSecureDesktop"; Value=1; Type="DWORD"; Description="UAC: Prompt on Secure Desktop"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Value=0; Type="DWORD"; Description="Disable Always Install Elevated (HKLM)"},
        @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Value=0; Type="DWORD"; Description="Disable Always Install Elevated (HKCU)"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_AllowNetBridge_NLA"; Value=0; Type="DWORD"; Description="Disable Network Bridge Installation"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_StdDomainUserSetLocation"; Value=1; Type="DWORD"; Description="Require elevation for network location"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="MinimumPIN"; Value=6; Type="DWORD"; Description="BitLocker Minimum PIN Length"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="UseAdvancedStartup"; Value=1; Type="DWORD"; Description="BitLocker Advanced Startup"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="EnableBDEWithNoTPM"; Value=0; Type="DWORD"; Description="BitLocker Require TPM"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="UseTPM"; Value=2; Type="DWORD"; Description="BitLocker Use TPM"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; Name="UseTPMPIN"; Value=2; Type="DWORD"; Description="BitLocker Use TPM+PIN"},
        @{Path="HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown"; Name="bDisableJavaScript"; Value=1; Type="DWORD"; Description="Disable Adobe Reader JavaScript"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ValidateAdminCodeSignatures"; Value=1; Type="DWORD"; Description="Validate Admin Code Signatures"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext"; Name="VersionCheckEnabled"; Value=1; Type="DWORD"; Description="Block Outdated ActiveX Controls"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="AllowGuest"; Value=0; Type="DWORD"; Description="Disable Guest Account"}
    )
    
    foreach ($setting in $regSettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            $originalValue = Get-OriginalRegistryValue -Path $setting.Path -Name $setting.Name
            New-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force | Out-Null
            Write-Host "[+] Set $($setting.Description)" -ForegroundColor Green
            Write-Log -Action $setting.Description -Result "Success" -Message "Path: $($setting.Path), Value: $($setting.Value)" -OriginalValue $originalValue
        }
        catch {
            Write-Host "[-] Failed to set $($setting.Description): $_" -ForegroundColor Red
            Write-Log -Action $setting.Description -Result "Failed" -Message $_.Exception.Message
        }
    }
}

 # Handle RDP Service based on user choice
    if ($DisableRDP) {
        Write-Host "`n[*] Disabling Remote Desktop Service..." -ForegroundColor Cyan
        try {
            # Disable RDP connections
            $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
            if (-not (Test-Path $rdpPath)) {
                New-Item -Path $rdpPath -Force | Out-Null
            }
            New-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -Value 1 -PropertyType DWORD -Force | Out-Null
            
            # Stop the RDP service
            try {
                Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
                Set-Service -Name "TermService" -StartupType Disabled -ErrorAction Stop
                Write-Host "[+] Remote Desktop service disabled and stopped" -ForegroundColor Green
                Write-Log -Action "Disable Remote Desktop" -Result "Success" -Message "RDP connections denied and service disabled"
            }
            catch {
                Write-Host "[+] Remote Desktop connections disabled (service handling failed, may need manual stop)" -ForegroundColor Yellow
                Write-Log -Action "Disable Remote Desktop" -Result "Partial" -Message "Registry set but service stop failed: $($_.Exception.Message)"
            }
        }
        catch {
            Write-Host "[-] Failed to disable Remote Desktop: $_" -ForegroundColor Red
            Write-Log -Action "Disable Remote Desktop" -Result "Failed" -Message $_.Exception.Message
        }
    }
    else {
        Write-Host "`n[!] Skipping Remote Desktop disabling (user declined)" -ForegroundColor Yellow
        Write-Host "[*] RDP security settings (TLS, NLA) will still be applied" -ForegroundColor Cyan
        Write-Log -Action "Disable Remote Desktop" -Result "Skipped" -Message "User chose to keep RDP enabled"
    }



function Disable-UnnecessaryServices {
    Write-Host "`n[*] Disabling Unnecessary Services..." -ForegroundColor Cyan
    
    $servicesToDisable = @(
        @{Name="RemoteRegistry"; Description="Remote Registry Service"},
        @{Name="TapiSrv"; Description="Telephony Service"},
        @{Name="WMPNetworkSvc"; Description="Windows Media Player Network Sharing"},
        @{Name="SharedAccess"; Description="Internet Connection Sharing"},
        @{Name="lfsvc"; Description="Geolocation Service"},
        @{Name="MapsBroker"; Description="Downloaded Maps Manager"},
        @{Name="NetTcpPortSharing"; Description="Net.Tcp Port Sharing Service"},
        @{Name="RemoteAccess"; Description="Routing and Remote Access"},
        @{Name="WerSvc"; Description="Windows Error Reporting"},
        @{Name="XblAuthManager"; Description="Xbox Live Auth Manager"},
        @{Name="XblGameSave"; Description="Xbox Live Game Save"},
        @{Name="XboxNetApiSvc"; Description="Xbox Live Networking Service"}
    )
    
    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service.Name -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Host "[+] Disabled $($service.Description)" -ForegroundColor Green
                Write-Log -Action "Disable Service: $($service.Description)" -Result "Success" -Message "Service: $($service.Name)"
            } else {
                Write-Log -Action "Disable Service: $($service.Description)" -Result "Skipped" -Message "Service not found: $($service.Name)"
            }
        }
        catch {
            Write-Host "[-] Could not disable $($service.Description)" -ForegroundColor Yellow
            Write-Log -Action "Disable Service: $($service.Description)" -Result "Failed" -Message $_.Exception.Message
        }
    }
}

function Enable-WindowsFirewall {
    Write-Host "`n[*] Configuring Windows Firewall..." -ForegroundColor Cyan
    
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        Write-Host "[+] Windows Firewall enabled for all profiles" -ForegroundColor Green
        Write-Log -Action "Windows Firewall Configuration" -Result "Success" -Message "All profiles enabled with default deny inbound"
    }
    catch {
        Write-Host "[-] Failed to configure Windows Firewall: $_" -ForegroundColor Red
        Write-Log -Action "Windows Firewall Configuration" -Result "Failed" -Message $_.Exception.Message
    }
}

function Set-PowerShellLogging {
    Write-Host "`n[*] Enabling PowerShell Logging..." -ForegroundColor Cyan
    
    $psLogging = @(
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name="EnableModuleLogging"; Value=1; Type="DWORD"; Description="Enable PowerShell Module Logging"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Value=1; Type="DWORD"; Description="Enable PowerShell Script Block Logging"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableTranscripting"; Value=1; Type="DWORD"; Description="Enable PowerShell Transcription"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableInvocationHeader"; Value=1; Type="DWORD"; Description="Enable PowerShell Invocation Header"}
    )
    
    foreach ($setting in $psLogging) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            New-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force | Out-Null
            Write-Log -Action $setting.Description -Result "Success" -Message "Path: $($setting.Path)"
        }
        catch {
            Write-Log -Action $setting.Description -Result "Failed" -Message $_.Exception.Message
        }
    }
    
    Write-Host "[+] PowerShell logging enabled" -ForegroundColor Green
}

function Set-WindowsUpdates {
    Write-Host "`n[*] Configuring Windows Update Settings..." -ForegroundColor Cyan
    
    try {
        $updatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $updatePath)) {
            New-Item -Path $updatePath -Force | Out-Null
        }
        
        New-ItemProperty -Path $updatePath -Name "NoAutoUpdate" -Value 0 -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $updatePath -Name "AUOptions" -Value 4 -PropertyType DWORD -Force | Out-Null
        
        Write-Host "[+] Windows Update configured for automatic installation" -ForegroundColor Green
        Write-Log -Action "Windows Update Configuration" -Result "Success" -Message "Automatic installation enabled"
    }
    catch {
        Write-Host "[-] Failed to configure Windows Update: $_" -ForegroundColor Red
        Write-Log -Action "Windows Update Configuration" -Result "Failed" -Message $_.Exception.Message
    }
}

function Set-DefenderExploitGuard {
    Write-Host "`n[*] Configuring Windows Defender Exploit Guard..." -ForegroundColor Cyan
    
    try {
        $cfaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
        if (-not (Test-Path $cfaPath)) {
            New-Item -Path $cfaPath -Force | Out-Null
        }
        New-ItemProperty -Path $cfaPath -Name "EnableControlledFolderAccess" -Value 1 -PropertyType DWORD -Force | Out-Null
        Write-Host "[+] Controlled Folder Access enabled" -ForegroundColor Green
        Write-Log -Action "Controlled Folder Access" -Result "Success" -Message "Protection enabled"
    }
    catch {
        Write-Host "[-] Failed to enable Controlled Folder Access: $_" -ForegroundColor Red
        Write-Log -Action "Controlled Folder Access" -Result "Failed" -Message $_.Exception.Message
    }
    
    Write-Host "[*] Enabling Attack Surface Reduction Rules..." -ForegroundColor Cyan
    
    $asrRules = @{
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
        "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
        "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macro"
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet prevalence, age, or trusted list criterion"
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from LSASS"
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    }
    
    foreach ($guid in $asrRules.Keys) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            Write-Host "[+] Enabled: $($asrRules[$guid])" -ForegroundColor Green
            Write-Log -Action "ASR Rule: $($asrRules[$guid])" -Result "Success" -Message "GUID: $guid"
        }
        catch {
            Write-Host "[-] Failed to enable: $($asrRules[$guid])" -ForegroundColor Yellow
            Write-Log -Action "ASR Rule: $($asrRules[$guid])" -Result "Failed" -Message $_.Exception.Message
        }
    }
}

function Enable-LAPS {
    Write-Host "`n[*] Checking for Local Admin Password Solution (LAPS)..." -ForegroundColor Cyan
    
    $lapsAvailable = Get-Command -Name Set-LapsADComputerSelfPermission -ErrorAction SilentlyContinue
    
    if ($lapsAvailable) {
        Write-Host "[+] LAPS is available. Configure via Group Policy" -ForegroundColor Green
        Write-Log -Action "LAPS Availability Check" -Result "Success" -Message "LAPS is available on this system"
    } else {
        Write-Host "[!] LAPS not detected. Consider deploying LAPS for local admin password management" -ForegroundColor Yellow
        Write-Log -Action "LAPS Availability Check" -Result "Not Found" -Message "LAPS is not installed on this system"
    }
}

function Disable-SMBv1Client {
    Write-Host "`n[*] Disabling SMBv1 Client Driver..." -ForegroundColor Cyan
    
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
        Write-Host "[+] SMBv1 client driver disabled" -ForegroundColor Green
        Write-Log -Action "Disable SMBv1 Protocol" -Result "Success" -Message "SMBv1 Windows feature disabled"
    }
    catch {
        Write-Host "[-] Could not disable SMBv1 client: $_" -ForegroundColor Yellow
        Write-Log -Action "Disable SMBv1 Protocol" -Result "Failed" -Message $_.Exception.Message
    }
}

function Apply-Hardening {
    param (
        [string]$Version
    )
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Hardening $Version" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Initialize logging
    Initialize-Logging -TargetOS $Version
    
    # Ask about TLS/SSL hardening
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  TLS/SSL Configuration" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "`nThis will:" -ForegroundColor White
    Write-Host "  - DISABLE: SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1" -ForegroundColor Red
    Write-Host "  - DISABLE: Weak ciphers (RC4, DES, 3DES)" -ForegroundColor Red
    Write-Host "  - ENABLE: TLS 1.2 and TLS 1.3 only" -ForegroundColor Green
    Write-Host "`nWARNING: Legacy applications may break!" -ForegroundColor Red
    Write-Host "Recommended for: New systems and modern environments" -ForegroundColor Yellow
    Write-Host ""
    
    do {
        $tlsChoice = Read-Host "Disable outdated TLS/SSL protocols and weak ciphers? (Y/N)"
        $tlsChoice = $tlsChoice.ToUpper()
    } while ($tlsChoice -ne 'Y' -and $tlsChoice -ne 'N')
    
    $applyTLS = ($tlsChoice -eq 'Y')

    # Ask about RDP disabling
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  Remote Desktop (RDP) Configuration" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "`nThis will:" -ForegroundColor White
    Write-Host "  - DISABLE: Remote Desktop connections" -ForegroundColor Red
    Write-Host "  - STOP: Terminal Services (RDP service)" -ForegroundColor Red
    Write-Host "`nWARNING: You will be disconnected if currently connected via RDP!" -ForegroundColor Red
    Write-Host "Recommended for: Systems that don't require remote access" -ForegroundColor Yellow
    Write-Host "Note: RDP security settings (TLS, NLA) will be applied regardless" -ForegroundColor Cyan
    Write-Host ""
    
    do {
        $rdpChoice = Read-Host "Disable Remote Desktop service? (Y/N)"
        $rdpChoice = $rdpChoice.ToUpper()
    } while ($rdpChoice -ne 'Y' -and $rdpChoice -ne 'N')
    
    $disableRDP = ($rdpChoice -eq 'Y')
    
    # Execute hardening steps
    Backup-Registry
    Set-AccountPolicies
    Set-AuditPolicies
    Set-RegistryHardening -DisableRDP $disableRDP
    Disable-UnnecessaryServices
    Enable-WindowsFirewall
    Set-PowerShellLogging
    Set-WindowsUpdates
    Set-DefenderExploitGuard
    Enable-LAPS
    Disable-SMBv1Client
    Set-TLSHardening -DisableOldTLS $applyTLS

    # Create Post-Hardening Registry Backup
    New-RegistryBackup
    
    # Final log entry
    Write-Log -Action "Script Completed" -Result "Success" -Message "All hardening steps completed for $Version"
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Hardening Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "`nRECOMMENDATIONS:" -ForegroundColor Yellow
    Write-Host "1. REBOOT THE SYSTEM to apply all changes"
    Write-Host "2. Test applications for compatibility"
    Write-Host "3. Review Event Logs for any issues"
    Write-Host "4. Update Windows Defender definitions"
    Write-Host "5. Run Windows Update"
    Write-Host "6. Configure LAPS via Group Policy if available"
    Write-Host "7. Review Attack Surface Reduction rules in Windows Security"
    
    if ($applyTLS) {
        Write-Host "`nTLS/SSL CHANGES APPLIED:" -ForegroundColor Red
        Write-Host "- TLS 1.0, TLS 1.1, SSL 2.0, SSL 3.0 have been DISABLED"
        Write-Host "- Only TLS 1.2 and TLS 1.3 are enabled"
        Write-Host "- Weak ciphers (RC4, DES, 3DES) have been disabled"
        Write-Host "- A REBOOT IS REQUIRED for TLS changes to take effect"
    } else {
        Write-Host "`nTLS/SSL CHANGES:" -ForegroundColor Yellow
        Write-Host "- TLS/SSL hardening was SKIPPED by user choice"
        Write-Host "- System still allows older protocols (less secure)"
    }
    
     if ($disableRDP) {
        Write-Host "`nREMOTE DESKTOP CHANGES APPLIED:" -ForegroundColor Red
        Write-Host "- Remote Desktop connections have been DISABLED"
        Write-Host "- Terminal Services (RDP service) has been stopped and disabled"
        Write-Host "- RDP security settings (TLS, NLA) have been applied"
        Write-Host "- Remote access to this system is now blocked"
    } else {
        Write-Host "`nREMOTE DESKTOP STATUS:" -ForegroundColor Yellow
        Write-Host "- Remote Desktop remains ENABLED (user choice)"
        Write-Host "- RDP security settings (TLS, NLA) have been applied"
        Write-Host "- Consider disabling RDP if remote access is not needed"
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Logs Saved" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Log file: $script:LogPath" -ForegroundColor White
    Write-Host "CSV file: $script:CsvPath" -ForegroundColor White
    Write-Host "Registry backups: C:\SecurityHardening\RegistryBackup_*.reg" -ForegroundColor White
    Write-Host "                  C:\SecurityHardening\NewRegistryBackup_*.reg" -ForegroundColor White
    Write-Host ""
}

# Main Script
do {
    Show-Menu
    $selection = Read-Host "Enter selection"
    
    switch ($selection) {
        '1' { Apply-Hardening -Version "Windows Server 2016" }
        '2' { Apply-Hardening -Version "Windows Server 2019" }
        '3' { Apply-Hardening -Version "Windows Server 2022" }
        '4' { Apply-Hardening -Version "Windows Server 2025" }
        '5' { Apply-Hardening -Version "Windows 10" }
        '6' { Apply-Hardening -Version "Windows 11" }
        'Q' { 
            Write-Host "`nExiting..." -ForegroundColor Yellow
            return 
        }
        default { 
            Write-Host "`nInvalid selection" -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
    
    if ($selection -match '[1-6]') {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Read-Host "Press ENTER to return to menu"
        Write-Host ""
    }
    
} while ($selection -ne 'Q')