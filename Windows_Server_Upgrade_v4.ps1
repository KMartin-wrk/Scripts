#Requires -RunAsAdministrator

# Windows Server GVLK Installation Script
Write-Host "Windows Server GVLK Installation Tool" -ForegroundColor Cyan
Write-Host "======================================`n" -ForegroundColor Cyan

# GVLK Keys for Windows Server versions
$GVLKKeys = @{
    "1"  = @{Name="Windows Server 2025 Standard"; Key="TVRH6-WHNXV-R9WG3-9XRFY-MY832"}
    "2"  = @{Name="Windows Server 2025 Datacenter"; Key="D764K-2NDRG-47T6Q-P8T8W-YP6DF"}
    "3"  = @{Name="Windows Server 2022 Standard"; Key="VDYBN-27WPP-V4HQT-9VMD4-VMK7H"}
    "4"  = @{Name="Windows Server 2022 Datacenter"; Key="WX4NM-KYWYW-QJJR4-XV3QB-6VM33"}
    "5"  = @{Name="Windows Server 2019 Standard"; Key="N69G4-B89J2-4G8F4-WWYCC-J464C"}
    "6"  = @{Name="Windows Server 2019 Datacenter"; Key="WMDGN-G9PQG-XVVXX-R3X43-63DFG"}
    "7"  = @{Name="Windows Server 2016 Standard"; Key="WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY"}
    "8"  = @{Name="Windows Server 2016 Datacenter"; Key="CB7KF-BWN84-R7R2Y-793K2-8XDDG"}
    "9"  = @{Name="Windows Server 2012 R2 Standard"; Key="D2N9P-3P6X9-2R39C-7RTCD-MDVJX"}
    "10" = @{Name="Windows Server 2012 R2 Datacenter"; Key="W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9"}
}

# Display menu
Write-Host "Select your Windows Server version:`n" -ForegroundColor Yellow
foreach ($key in ($GVLKKeys.Keys | Sort-Object {[int]$_})) {
    Write-Host "  [$key] $($GVLKKeys[$key].Name)"
}
Write-Host "`n  [Q] Quit`n" -ForegroundColor Gray

# Get user selection
do {
    $selection = Read-Host "Enter your choice"
    
    if ($selection -eq "Q" -or $selection -eq "q") {
        Write-Host "`nExiting..." -ForegroundColor Yellow
        exit
    }
    
    if ($GVLKKeys.ContainsKey($selection)) {
        $selectedVersion = $GVLKKeys[$selection]
        break
    }
    else {
        Write-Host "Invalid selection. Please try again.`n" -ForegroundColor Red
    }
} while ($true)

# Confirm selection
Write-Host "`nYou selected: $($selectedVersion.Name)" -ForegroundColor Green
Write-Host "GVLK: $($selectedVersion.Key)`n" -ForegroundColor Gray

$confirm = Read-Host "Do you want to apply this key? (Y/N)"
if ($confirm -ne "Y" -and $confirm -ne "y") {
    Write-Host "`nOperation cancelled." -ForegroundColor Yellow
    exit
}

# Apply GVLK using DISM
Write-Host "`nApplying GVLK..." -ForegroundColor Cyan
Write-Host "This may take a moment, please wait...`n" -ForegroundColor Yellow

try {
    # Run DISM command silently in background
    $dismArgs = "/Online /Set-Edition:ServerStandard /ProductKey:$($selectedVersion.Key) /AcceptEula"
    
    $process = Start-Process -FilePath "DISM.exe" -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
        Write-Host "`nGVLK installation completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "`nGVLK installation completed (Exit Code: $($process.ExitCode))" -ForegroundColor Yellow
    }
    
    Write-Host "`nThe system will restart in 30 seconds to apply the changes..." -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to cancel the restart." -ForegroundColor Gray
    
    Start-Sleep -Seconds 5
    
    shutdown /r /t 25 /c "Restarting to complete Windows Server GVLK installation"
}
catch {
    Write-Host "`nAn error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`nAlternative method using slmgr.vbs:" -ForegroundColor Yellow
    Write-Host "  slmgr.vbs /ipk $($selectedVersion.Key)" -ForegroundColor Gray
}

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")