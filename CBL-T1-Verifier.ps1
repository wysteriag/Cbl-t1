<#
.SYNOPSIS
    CBL Tier 1 Pro Verification - Advanced Anti-Cheat System
.DESCRIPTION
    Checks Windows security settings, scans for installed cheats/executors (Matcha, Xeno, Matrix, etc.),
    looks for leftover files/folders/registry entries, and displays real-time processes.
    Must be run as Administrator.
#>

# ===============================
# CBL TIER 1 PRO VERIFICATION
# ===============================

# ASCII Banner - CBL T1
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

Write-Host "  ==========================================" -ForegroundColor Cyan
Write-Host "  |    CBL TIER 1 PRO VERIFICATION        |" -ForegroundColor Cyan
Write-Host "  |    Advanced Anti-Cheat System         |" -ForegroundColor Cyan
Write-Host "  ==========================================" -ForegroundColor Cyan

# Check Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Please run PowerShell as Administrator!" -ForegroundColor Red
    exit 1
}

# ========== 1. SECURITY SETTINGS CHECK ==========
Write-Host "`n[1] CHECKING SECURITY SETTINGS...`n" -ForegroundColor Yellow

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

# ========== 2. CHEAT SCANNER (Advanced) ==========
Write-Host "`n[2] SCANNING FOR CHEAT INDICATORS (Installations, Files, Registry)...`n" -ForegroundColor Yellow

$cheatFound = $false
$cheatList = @()

# --- 2.1 Extended Cheat Process Names ---
$cheatProcesses = @(
    # Roblox Executors
    "xeno", "matcha", "matrix", "synapse", "krnl", "fluxus", "jjsploit", "electron", "scriptware", "vega", "celery", "evon", "hydrogen", "argon", "ozark", "meme", "easyexploit", "redtrust",
    # Other Cheat Tools
    "cheatengine", "cheatengine-x86_64", "ce", "autohotkey", "ahk", "macrorecorder", "macrorecorder.exe", "tinytask", "pulover's macro creator", "macrocreator",
    # Injectors/Debuggers
    "injector", "extremeinjector", "xenos", "ghidra", "ollydbg", "x64dbg", "ida", "windbg", "scylla", "lordpe", "studype", "dnspy", "de4dot", "processhacker"
)

# --- 2.2 Cheat Services ---
$cheatServices = @("cheatservice", "antidebug", "macroservice", "xenoservice", "bypassservice")

# --- 2.3 Extended Cheat Folders (Common installation paths) ---
$cheatFolders = @(
    # Common executor folders
    "$env:USERPROFILE\Desktop\Xeno", "$env:USERPROFILE\Desktop\Xeno Executor", "$env:USERPROFILE\Desktop\Matcha", "$env:USERPROFILE\Desktop\Matcha Executor", "$env:USERPROFILE\Desktop\Matrix", "$env:USERPROFILE\Desktop\Matrix Executor",
    "$env:USERPROFILE\Downloads\Xeno", "$env:USERPROFILE\Downloads\Matcha", "$env:USERPROFILE\Downloads\Matrix",
    "$env:USERPROFILE\Documents\Xeno", "$env:USERPROFILE\Documents\Matcha", "$env:USERPROFILE\Documents\Matrix",
    "$env:ProgramData\cheatengine", "$env:ProgramData\Xeno", "$env:ProgramData\Matcha", "$env:ProgramData\Matrix",
    "$env:APPDATA\AutoHotkey", "$env:APPDATA\Krnl", "$env:APPDATA\Synapse", "$env:APPDATA\Xeno", "$env:APPDATA\Matcha", "$env:APPDATA\Matrix",
    "$env:LOCALAPPDATA\Xeno", "$env:LOCALAPPDATA\Matcha", "$env:LOCALAPPDATA\Matrix",
    # Common cheat tool paths
    "$env:ProgramFiles\Cheat Engine", "${env:ProgramFiles(x86)}\Cheat Engine", "$env:ProgramFiles\AutoHotkey", "${env:ProgramFiles(x86)}\AutoHotkey"
)

# --- 2.4 Extended Registry Keys ---
$cheatRegKeys = @(
    "HKLM:\SOFTWARE\CheatEngine", "HKCU:\SOFTWARE\CheatEngine",
    "HKLM:\SOFTWARE\AutoHotkey", "HKCU:\SOFTWARE\AutoHotkey",
    "HKLM:\SOFTWARE\Xeno", "HKCU:\SOFTWARE\Xeno",
    "HKLM:\SOFTWARE\Matcha", "HKCU:\SOFTWARE\Matcha",
    "HKLM:\SOFTWARE\Matrix", "HKCU:\SOFTWARE\Matrix",
    "HKLM:\SOFTWARE\Krnl", "HKCU:\SOFTWARE\Krnl",
    "HKLM:\SOFTWARE\Synapse", "HKCU:\SOFTWARE\Synapse",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Cheat*", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Cheat*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Xeno*", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Xeno*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Matcha*", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Matcha*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Matrix*", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Matrix*"
)

# --- 2.5 Known Cheat File Names (to search in common locations) ---
$cheatFiles = @(
    "xeno.exe", "xeno.dll", "xeno injector.exe", "matcha.exe", "matcha injector.exe", "matrix.exe", "matrix injector.exe",
    "synapse.exe", "synapse.dll", "krnl.exe", "krnl.dll", "fluxus.exe", "jjsploit.exe", "electron.exe", "scriptware.exe",
    "cheatengine.exe", "cheatengine-x86_64.exe", "autohotkey.exe", "ahk.exe", "macrorecorder.exe", "tinytask.exe",
    "injector.exe", "extremeinjector.exe", "xenos.exe", "ghidra.exe", "ollydbg.exe", "x64dbg.exe", "ida.exe", "windbg.exe"
)

# --- 2.6 Scan Processes ---
Write-Host "  Scanning running processes..." -ForegroundColor Gray
$runningProcesses = Get-Process | Select-Object -ExpandProperty Name
foreach ($cheat in $cheatProcesses) {
    if ($runningProcesses -match $cheat) {
        Write-Host "    [!] Suspicious process: $cheat" -ForegroundColor Red
        $cheatFound = $true
        $cheatList += "Process: $cheat"
    }
}

# --- 2.7 Scan Services ---
Write-Host "  Scanning services..." -ForegroundColor Gray
$services = Get-Service | Select-Object -ExpandProperty Name
foreach ($cheat in $cheatServices) {
    if ($services -match $cheat) {
        Write-Host "    [!] Suspicious service: $cheat" -ForegroundColor Red
        $cheatFound = $true
        $cheatList += "Service: $cheat"
    }
}

# --- 2.8 Scan Folders ---
Write-Host "  Scanning common cheat folders..." -ForegroundColor Gray
foreach ($folder in $cheatFolders) {
    if (Test-Path $folder) {
        Write-Host "    [!] Suspicious folder found: $folder" -ForegroundColor Red
        $cheatFound = $true
        $cheatList += "Folder: $folder"
    }
}

# --- 2.9 Scan Registry ---
Write-Host "  Scanning registry keys..." -ForegroundColor Gray
foreach ($regPath in $cheatRegKeys) {
    if (Test-Path $regPath) {
        Write-Host "    [!] Suspicious registry key: $regPath" -ForegroundColor Red
        $cheatFound = $true
        $cheatList += "Registry: $regPath"
    }
}

# --- 2.10 Scan for Cheat Files in User Folders (Desktop, Downloads, Documents) ---
Write-Host "  Scanning for known cheat files in user folders..." -ForegroundColor Gray
$userFolders = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents")
foreach ($folder in $userFolders) {
    foreach ($file in $cheatFiles) {
        $filePath = Join-Path $folder $file
        if (Test-Path $filePath) {
            Write-Host "    [!] Suspicious file found: $filePath" -ForegroundColor Red
            $cheatFound = $true
            $cheatList += "File: $filePath"
        }
    }
}

# --- 2.11 Scan for recently downloaded files (last 30 days) that might be cheats ---
Write-Host "  Scanning for recently downloaded cheat files (last 30 days)..." -ForegroundColor Gray
$recentCutoff = (Get-Date).AddDays(-30)
$downloadFolders = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP")
$suspiciousExtensions = @(".exe", ".dll", ".ahk", ".lua", ".zip", ".rar", ".7z", ".msi")
$suspiciousKeywords = @("cheat", "hack", "exploit", "executor", "injector", "xeno", "matcha", "matrix", "synapse", "krnl", "fluxus", "jjsploit", "aimbot", "esp", "wallhack", "bypass", "auto", "macro", "script")

foreach ($folder in $downloadFolders) {
    if (Test-Path $folder) {
        $recentFiles = Get-ChildItem -Path $folder -Recurse -ErrorAction SilentlyContinue | Where-Object {
            $_.LastWriteTime -gt $recentCutoff -and $suspiciousExtensions -contains $_.Extension -and
            ($suspiciousKeywords -contains $_.BaseName -or $suspiciousKeywords -match $_.BaseName)
        }
        foreach ($file in $recentFiles) {
            Write-Host "    [!] Recently downloaded suspicious file: $($file.FullName)" -ForegroundColor Red
            $cheatFound = $true
            $cheatList += "Recent Download: $($file.FullName)"
        }
    }
}

# --- 2.12 Check for kernel drivers related to cheats ---
Write-Host "  Scanning kernel drivers..." -ForegroundColor Gray
$driverList = Get-WinDriver | Where-Object { $_.DriverName -match "cheat|hook|inject|bypass|xeno|matcha|matrix" }
if ($driverList) {
    Write-Host "    [!] Suspicious kernel drivers found:" -ForegroundColor Red
    $driverList | ForEach-Object {
        Write-Host "        - $($_.DriverName)" -ForegroundColor Red
        $cheatFound = $true
        $cheatList += "Driver: $($_.DriverName)"
    }
}

# Final result
if (-not $cheatFound) {
    Write-Host "  ✓ No known cheats detected." -ForegroundColor Green
} else {
    Write-Host "`n  [ALERT] Cheat indicators found! This recording may be rejected." -ForegroundColor Red
    Write-Host "`n  Suspicious items found:" -ForegroundColor Yellow
    $cheatList | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
}

# ========== 3. REAL-TIME PROCESS MONITOR (Separate Window) ==========
Write-Host "`n[3] OPENING REAL-TIME PROCESS MONITOR..." -ForegroundColor Yellow
Write-Host "  A new window will open showing all running processes." -ForegroundColor Cyan
Write-Host "  Scroll through the list to show ALL processes. Close the window to continue." -ForegroundColor Cyan
Write-Host "  Press any key to continue..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Start the process monitor in a separate PowerShell window
$monitorScript = {
    $refreshInterval = 2
    while ($true) {
        Clear-Host
        Write-Host "=== CBL TIER 1 PRO - REAL-TIME PROCESS MONITOR ===" -ForegroundColor Cyan
        Write-Host "Updated: $(Get-Date -Format 'HH:mm:ss') | Refreshes every $refreshInterval seconds"
        Write-Host "Scroll to view all processes. Close this window to stop monitoring.`n"
        
        Get-Process | Sort-Object -Property ProcessName | Format-Table -Property Id, ProcessName, CPU, @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet64/1MB,2)}}, StartTime -AutoSize
        
        Start-Sleep -Seconds $refreshInterval
    }
}

# Launch monitor in a new window
Start-Process powershell -ArgumentList "-NoExit -Command & { $monitorScript }"

Write-Host "`n[+] CBL Tier 1 Pro verification completed." -ForegroundColor Green
Write-Host "    Make sure to show the process monitor window and scroll through all processes." -ForegroundColor Yellow
Write-Host "    Stop recording and submit the video." -ForegroundColor Green
