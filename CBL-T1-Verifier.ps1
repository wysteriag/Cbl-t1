<#
.SYNOPSIS
    CBL Tier 1 Verification System - Anti-Cheat & Compliance Checker
.DESCRIPTION
    Checks Windows security settings, scans for known cheats, and displays real-time processes.
    Must be run as Administrator.
#>

# ===============================
# CBL TIER 1 VERIFICATION SYSTEM
# ===============================

# ASCII Banner - CBL T1 (approved version)
Write-Host @"
 ██████╗██████╗ ██╗     
██╔════╝██╔══██╗██║     
██║     ██████╔╝██║     
██║     ██╔══██╗██║     
╚██████╗██████╔╝███████╗
 ╚═════╝╚═════╝ ╚══════╝
 ████████╗ ██╗   
 ╚══██╔══╝██╔╝   
    ██║  ██╔╝    
    ██║  ██╔╝    
    ██║  ██║     
    ╚═╝  ╚═╝     
"@ -ForegroundColor Cyan

Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "  |       CBL TIER 1 VERIFICATION        |" -ForegroundColor Cyan
Write-Host "  |         Anti-Cheat System            |" -ForegroundColor Cyan
Write-Host "  ========================================" -ForegroundColor Cyan

# Check Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Please run PowerShell as Administrator!" -ForegroundColor Red
    exit 1
}

# ========== 1. SECURITY SETTINGS CHECK ==========
Write-Host "`n[1] CHECKING SECURITY SETTINGS...`n" -ForegroundColor Yellow

# Helper function
function Test-Setting {
    param($Condition, $PassMessage, $FailMessage)
    if ($Condition) {
        Write-Host "  ✓ $PassMessage" -ForegroundColor Green
        return $true
    } else {
        Write-Host "  ✗ $FailMessage" -ForegroundColor Red
        return $false
    }
}

# 1.1 Windows Defender Notifications
$defender = Get-MpPreference
Test-Setting -Condition ($defender.DisableNotifications -eq $false) `
    -PassMessage "Defender Notifications: ENABLED" `
    -FailMessage "Defender Notifications: DISABLED"

# 1.2 Real-time Protection
$rtp = (Get-MpComputerStatus).RealTimeProtectionEnabled
Test-Setting -Condition ($rtp -eq $true) `
    -PassMessage "Real-time Protection: ACTIVE" `
    -FailMessage "Real-time Protection: INACTIVE"

# 1.3 Firewall
$fwOff = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }
Test-Setting -Condition (-not $fwOff) `
    -PassMessage "Windows Firewall: ACTIVE on all profiles" `
    -FailMessage "Windows Firewall: DISABLED on some profile"

# 1.4 Exclusions & Allowed Threats
$exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
$allowedThreats = Get-MpPreference | Select-Object -ExpandProperty ThreatIDDefaultAction_Ids
Test-Setting -Condition (-not $exclusions -and -not $allowedThreats) `
    -PassMessage "Exclusions & Allowed Threats: EMPTY" `
    -FailMessage "Exclusions or Allowed Threats: FOUND"

# 1.5 Memory Integrity
$memoryIntegrity = (Get-DeviceGuard).MemoryIntegrityEnabled
Test-Setting -Condition ($memoryIntegrity -eq $true) `
    -PassMessage "Memory Integrity: ENABLED" `
    -FailMessage "Memory Integrity: DISABLED"

# 1.6 Vulnerable Driver Block list
$vulnDriver = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
Test-Setting -Condition ($vulnDriver.Enabled -eq 1) `
    -PassMessage "Vulnerable Driver Block list: ENABLED" `
    -FailMessage "Vulnerable Driver Block list: DISABLED"

# 1.7 Performance Options
$visualFX = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -ErrorAction SilentlyContinue).VisualFXSetting
if ($visualFX -eq 1 -or $visualFX -eq 0 -or $visualFX -eq $null) {
    Write-Host "  ✓ Performance options: ALL ENABLED (or default)" -ForegroundColor Green
} else {
    Write-Host "  ✗ Performance options: SOME DISABLED" -ForegroundColor Red
}

# 1.8 UAC Level
$uacLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").ConsentPromptBehaviorAdmin
if ($uacLevel -eq 3) {
    Write-Host "  ✓ UAC Level: SECOND LOWEST (correct)" -ForegroundColor Green
} else {
    Write-Host "  ✗ UAC Level: $uacLevel (expected 3)" -ForegroundColor Red
}

# 1.9 Multiple monitors
$monitors = (Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams).Count
if ($monitors -le 1) {
    Write-Host "  ✓ Monitors detected: $monitors (single monitor)" -ForegroundColor Green
} else {
    Write-Host "  ✗ Multiple monitors detected: $monitors" -ForegroundColor Red
}

# Manual checks reminder
Write-Host "`n  [MANUAL CHECK] Press Win+Tab and show only 1 desktop." -ForegroundColor Yellow
Write-Host "  [MANUAL CHECK] No USB/hotkey icons in system tray." -ForegroundColor Yellow

# ========== 2. CHEAT SCANNER ==========
Write-Host "`n[2] SCANNING FOR SUSPICIOUS CHEAT INDICATORS...`n" -ForegroundColor Yellow

# Known cheat process names (expand as needed)
$cheatProcesses = @(
    "cheatengine", "cheatengine-x86_64", "ce", "autohotkey", "ahk", "macrorecorder", 
    "injector", "extremeinjector", "processhacker", "xenos", "ghidra", "ollydbg", 
    "x64dbg", "ida", "windbg", "scylla", "lordpe", "studype", "dnspy", "de4dot",
    "redtrust", "synapse", "krnl", "jjsploit", "electron", "scriptware", "vega"
)

# Known cheat services
$cheatServices = @("cheatservice", "antidebug", "macroservice")

# Known cheat folders
$cheatFolders = @(
    "$env:USERPROFILE\Desktop\cheats",
    "$env:USERPROFILE\Downloads\cheats",
    "$env:USERPROFILE\Documents\cheats",
    "$env:ProgramData\cheatengine",
    "$env:APPDATA\AutoHotkey",
    "$env:APPDATA\Krnl",
    "$env:APPDATA\Synapse"
)

# Known registry keys
$cheatRegKeys = @(
    "HKLM:\SOFTWARE\CheatEngine",
    "HKCU:\SOFTWARE\AutoHotkey",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Cheat*"
)

$cheatFound = $false

# Check processes
Write-Host "  Scanning running processes..." -ForegroundColor Gray
$runningProcesses = Get-Process | Select-Object -ExpandProperty Name
foreach ($cheat in $cheatProcesses) {
    if ($runningProcesses -match $cheat) {
        Write-Host "    [!] Suspicious process: $cheat" -ForegroundColor Red
        $cheatFound = $true
    }
}

# Check services
Write-Host "  Scanning services..." -ForegroundColor Gray
$services = Get-Service | Select-Object -ExpandProperty Name
foreach ($cheat in $cheatServices) {
    if ($services -match $cheat) {
        Write-Host "    [!] Suspicious service: $cheat" -ForegroundColor Red
        $cheatFound = $true
    }
}

# Check folders
Write-Host "  Scanning common cheat folders..." -ForegroundColor Gray
foreach ($folder in $cheatFolders) {
    if (Test-Path $folder) {
        Write-Host "    [!] Suspicious folder found: $folder" -ForegroundColor Red
        $cheatFound = $true
    }
}

# Check registry
Write-Host "  Scanning registry keys..." -ForegroundColor Gray
foreach ($regPath in $cheatRegKeys) {
    if (Test-Path $regPath) {
        Write-Host "    [!] Suspicious registry key: $regPath" -ForegroundColor Red
        $cheatFound = $true
    }
}

# Check kernel drivers
$driverList = Get-WinDriver | Where-Object { $_.DriverName -match "cheat|hook|inject|bypass" }
if ($driverList) {
    Write-Host "    [!] Suspicious kernel drivers found:" -ForegroundColor Red
    $driverList | ForEach-Object { Write-Host "        - $($_.DriverName)" -ForegroundColor Red }
    $cheatFound = $true
}

if (-not $cheatFound) {
    Write-Host "  ✓ No known cheats detected." -ForegroundColor Green
} else {
    Write-Host "`n  [ALERT] Cheat indicators found! This recording may be rejected." -ForegroundColor Red
}

# ========== 3. REAL-TIME PROCESS MONITOR ==========
Write-Host "`n[3] REAL-TIME PROCESS MONITOR (press Q to stop)...`n" -ForegroundColor Yellow
Write-Host "  Instructions: Scroll up/down to show ALL processes. Refreshes every 2 seconds." -ForegroundColor Cyan

while ($true) {
    Clear-Host
    # Show banner again for aesthetics
    Write-Host @"
 ██████╗██████╗ ██╗     
██╔════╝██╔══██╗██║     
██║     ██████╔╝██║     
██║     ██╔══██╗██║     
╚██████╗██████╔╝███████╗
 ╚═════╝╚═════╝ ╚══════╝
 ████████╗ ██╗   
 ╚══██╔══╝██╔╝   
    ██║  ██╔╝    
    ██║  ██╔╝    
    ██║  ██║     
    ╚═╝  ╚═╝     
"@ -ForegroundColor Cyan
    Write-Host "  REAL-TIME PROCESS LIST (updated: $(Get-Date -Format 'HH:mm:ss'))`n" -ForegroundColor Green
    Get-Process | Sort-Object -Property ProcessName | Format-Table -Property Id, ProcessName, CPU, @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet64/1MB,2)}} -AutoSize
    Write-Host "`n  [Press Q to exit monitoring]" -ForegroundColor Yellow
    
    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    if ($key.Character -eq 'q' -or $key.Character -eq 'Q') {
        break
    }
    Start-Sleep -Seconds 2
}

Write-Host "`n[+] CBL Tier 1 verification completed. Stop recording and submit the video." -ForegroundColor Green
