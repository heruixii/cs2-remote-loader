# Gamma-A Verification Script - Run as Administrator
# Verifies that kernel debug mode is active (PatchGuard disabled)

$LogFile = "$env:TEMP\gamma_a_verify.log"
"" | Out-File -FilePath $LogFile -Encoding UTF8

function Write-Log {
    param([string]$msg)
    $msg | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host $msg
}

Write-Log "============================================================"
Write-Log " Gamma-A Verification Script"
Write-Log " Time: $(Get-Date)"
Write-Log "============================================================"
Write-Log ""

# Check 1: Administrator privileges
Write-Log "[1] Administrator privileges:"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Log "    Admin: $isAdmin"
Write-Log ""

# Check 2: BCD configuration
Write-Log "[2] BCD Configuration (bcdedit):"
$bcdOutput = & bcdedit.exe /enum "{current}" 2>&1
$bcdStr = $bcdOutput | Out-String
Write-Log $bcdStr
Write-Log ""

# Check 3: Extract debug and testsigning status
Write-Log "[3] Key Settings:"
$debugLine = $bcdStr -split "`n" | Where-Object { $_ -match "^\s*debug\s" }
$testsigningLine = $bcdStr -split "`n" | Where-Object { $_ -match "^\s*testsigning\s" }
Write-Log "    $debugLine"
Write-Log "    $testsigningLine"
Write-Log ""

# Check 4: WMI Debug status
Write-Log "[4] WMI Operating System Debug status:"
$os = Get-WmiObject Win32_OperatingSystem
Write-Log "    OS Debug: $($os.Debug)"
Write-Log ""

# Check 5: Check if PatchGuard is disabled via debug mode
Write-Log "[5] PatchGuard Status Analysis:"
if ($debugLine -match "Yes") {
    Write-Log "    [OK] debug=Yes - Kernel debug mode is ACTIVE"
    Write-Log "    [OK] PatchGuard should NOT initialize on this boot"
    Write-Log "    [OK] DKOM can be used permanently"
} else {
    Write-Log "    [FAIL] debug is NOT Yes - Kernel debug mode not active"
    Write-Log "    [FAIL] PatchGuard may still be active"
}
Write-Log ""

# Check 6: Test signing watermark
if ($testsigningLine -match "Yes") {
    Write-Log "    [INFO] testsigning=Yes - Test mode watermark WILL appear on desktop"
} else {
    Write-Log "    [OK] testsigning=No - No test mode watermark"
}
Write-Log ""

Write-Log "============================================================"
Write-Log " Verification Complete"
Write-Log " Log file: $LogFile"
Write-Log "============================================================"

Write-Host ""
Write-Host "Log saved to: $LogFile"
Write-Host ""
Read-Host "Press Enter to exit"
