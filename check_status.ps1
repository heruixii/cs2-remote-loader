$proc = Get-Process loader -ErrorAction SilentlyContinue
if ($proc) {
    $elapsed = (Get-Date) - $proc.StartTime
    Write-Host ("=== loader.exe RUNNING ===")
    Write-Host ("PID: " + $proc.Id + "  Elapsed: " + [int]$elapsed.TotalSeconds + "s (" + [math]::Round($elapsed.TotalMinutes, 2) + " min)")
    Write-Host ("CPU: " + $proc.CPU + "s  WorkingSet: " + [math]::Round($proc.WorkingSet/1MB, 2) + " MB")
} else {
    Write-Host "=== loader.exe NOT RUNNING ==="
}

Write-Host ""
$logPath = Join-Path $env:TEMP "stealth_diag.log"
if (Test-Path $logPath) {
    $lines = Get-Content $logPath
    Write-Host ("Log Lines: " + $lines.Count)
    Write-Host "=== First 8 lines ==="
    $lines[0..7] | ForEach-Object { Write-Host $_ }
    Write-Host "=== Last 15 lines ==="
    $lines[-15..-1] | ForEach-Object { Write-Host $_ }
    Write-Host "=== F= entries (last 5) ==="
    $fentries = $lines | Select-String -Pattern "^F=\d+"
    if ($fentries.Count -gt 0) {
        $fentries[-5..-1] | ForEach-Object { Write-Host $_.Line }
    }
    Write-Host "=== CRASH/FAIL/ERROR entries ==="
    $issues = $lines | Select-String -Pattern "CRASH|FAIL|ERROR|TIMEOUT|cooldown"
    if ($issues.Count -gt 0) {
        $issues | ForEach-Object { Write-Host ("L" + $_.LineNumber + ": " + $_.Line) }
    } else {
        Write-Host "(none)"
    }
} else {
    Write-Host "Log not yet created"
}
