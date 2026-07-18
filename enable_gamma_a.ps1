# Gamma-A Enable Script (PowerShell version)
# Run as Administrator: Right-click -> Run with PowerShell as Administrator

$LogFile = "$env:TEMP\gamma_a_enable.log"

function Write-Log {
    param([string]$msg)
    $msg | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host $msg
}

# Clear previous log
"" | Out-File -FilePath $LogFile -Encoding UTF8

Write-Log "============================================================"
Write-Log " Gamma-A: PatchGuard Disabler (PowerShell Version)"
Write-Log " Time: $(Get-Date)"
Write-Log "============================================================"
Write-Log ""

# Check administrator privileges
Write-Log "[1] Checking administrator privileges..."
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "[FAIL] NOT running as administrator!"
    Write-Log "Please right-click PowerShell -> Run as Administrator"
    Write-Log "Then run: powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\enable_gamma_a.ps1`""
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Log "[OK] Running as administrator"
Write-Log ""

# Step 0: Check current status
Write-Log "[2] Current debug status (before changes):"
try {
    $os = Get-WmiObject Win32_OperatingSystem
    Write-Log "    OS Debug mode: $($os.Debug)"
} catch {
    Write-Log "    WMI check failed: $_"
}
Write-Log ""

# Step 1: Enable kernel debug mode
Write-Log "[3] Step 1/3: Enable kernel debug mode..."
$result = & bcdedit.exe /debug on 2>&1
$exitCode = $LASTEXITCODE
Write-Log "    Output: $result"
Write-Log "    Exit code: $exitCode"
if ($exitCode -ne 0) {
    Write-Log "[ERROR] bcdedit /debug on failed!"
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Log "[OK] Kernel debug mode enabled"
Write-Log ""

# Step 2: Configure debug settings
Write-Log "[4] Step 2/3: Configure debug settings..."
$result = & bcdedit.exe /dbgsettings serial debugport:1 baudrate:115200 /start autoenable /noumex 2>&1
$exitCode = $LASTEXITCODE
Write-Log "    Output: $result"
Write-Log "    Exit code: $exitCode"
if ($exitCode -ne 0) {
    Write-Log "[WARNING] dbgsettings failed (may already be configured), continuing..."
} else {
    Write-Log "[OK] Debug settings configured"
}
Write-Log ""

# Step 3: Disable test signing watermark
Write-Log "[5] Step 3/3: Disable test signing watermark..."
$result = & bcdedit.exe /set testsigning off 2>&1
$exitCode = $LASTEXITCODE
Write-Log "    Output: $result"
Write-Log "    Exit code: $exitCode"
if ($exitCode -ne 0) {
    Write-Log "[WARNING] testsigning setting failed (may already be off), continuing..."
} else {
    Write-Log "[OK] Test signing watermark disabled"
}
Write-Log ""

# Final verification
Write-Log "[6] Final BCD status (after changes):"
$result = & bcdedit.exe /enum "{current}" 2>&1
$resultStr = $result | Out-String
Write-Log $resultStr
Write-Log ""

# Summary
Write-Log "============================================================"
Write-Log " Gamma-A Configuration Complete!"
Write-Log " Log file: $LogFile"
Write-Log "============================================================"
Write-Log ""
Write-Log "Important Notes:"
Write-Log "  1. You MUST restart the system for configuration to take effect"
Write-Log "  2. After restart, PatchGuard will NOT initialize"
Write-Log "  3. DKOM can be used permanently"
Write-Log "  4. Test Mode watermark may appear (normal)"
Write-Log ""
Write-Log "Restart command: shutdown /r /t 0"
Write-Log ""

Write-Host ""
Write-Host "Log saved to: $LogFile"
Write-Host ""
Read-Host "Press Enter to exit"
