<#
.SYNOPSIS
  Integration tests for PhantomFS. Exercises the ProjFS provider end to end:
  projection, enumeration, placeholder alerts, content-read alerts, Event Log
  entries, and the auto-cleanup revert cycle.

.REQUIREMENTS
  - Windows 10 v1809+ with the Client-ProjFS optional feature enabled
  - Elevated (Administrator) PowerShell session
  - PhantomFS.exe and PhantomFS.exe.config in the same directory as this script

.USAGE
  .\Invoke-PhantomFSIntegrationTests.ps1
  Exit code 0 = all tests passed, 1 = one or more failures.
#>

[CmdletBinding()]
param(
    [string]$PhantomFSPath = (Join-Path $PSScriptRoot 'PhantomFS.exe'),
    [string]$ConfigPath    = (Join-Path $PSScriptRoot 'PhantomFS.exe.config'),
    [int]$CleanupDelaySeconds = 35   # short delay so the revert cycle is testable
)

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:Passed++
        Write-Host ("  [PASS] " + $Name) -ForegroundColor Green
    } else {
        $script:Failed++
        Write-Host ("  [FAIL] " + $Name) -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
Write-Host 'PhantomFS integration tests' -ForegroundColor Cyan
Write-Host ('-' * 50)

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this script from an elevated PowerShell session.' }

$projFs = Get-WindowsOptionalFeature -Online -FeatureName Client-ProjFS
if ($projFs.State -ne 'Enabled') {
    throw 'Client-ProjFS is not enabled. Run: Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart'
}

if (-not (Test-Path $PhantomFSPath)) { throw ('PhantomFS.exe not found: ' + $PhantomFSPath) }
if (-not (Test-Path $ConfigPath))    { throw ('Config not found: ' + $ConfigPath) }

# ---------------------------------------------------------------------------
# Test environment: fresh virtroot, test copy of the exe and config with a
# short cleanup delay and Toast disabled (Toast cannot be asserted headlessly).
# ---------------------------------------------------------------------------
$testRoot = Join-Path $env:TEMP ('phantomfs-it-' + [Guid]::NewGuid().ToString('N'))
$virtRoot = Join-Path $testRoot 'Honeypot'
New-Item -ItemType Directory -Path $testRoot | Out-Null

$testExe    = Join-Path $testRoot 'PhantomFS.exe'
$testConfig = $testExe + '.config'
Copy-Item $PhantomFSPath $testExe

[xml]$configXml = Get-Content $ConfigPath -Raw
$configXml.configuration.settings.enableToast              = 'false'
$configXml.configuration.settings.autoCleanupEnabled       = 'true'
$configXml.configuration.settings.autoCleanupDelaySeconds  = [string]$CleanupDelaySeconds
$configXml.configuration.settings.verbose                  = 'true'
$configXml.Save($testConfig)

$testStart = Get-Date

# ---------------------------------------------------------------------------
# Start the provider. Stdin is redirected so ENTER can be sent to stop it.
# ---------------------------------------------------------------------------
$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName               = $testExe
$startInfo.Arguments              = ('--virtroot "' + $virtRoot + '" --syntheticonly')
$startInfo.UseShellExecute        = $false
$startInfo.RedirectStandardInput  = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError  = $true
$provider = [System.Diagnostics.Process]::Start($startInfo)

# Drain stdout/stderr asynchronously. Redirected pipes that are never read
# fill up (~4KB) and then block the provider on its next Console.WriteLine,
# which stalls the cleanup timer thread and deadlocks the revert cycle.
$script:ProviderOutput = [System.Text.StringBuilder]::new()
$outputHandler = {
    if ($EventArgs.Data) {
        [void]$Event.MessageData.AppendLine($EventArgs.Data)
    }
}
$stdoutEvent = Register-ObjectEvent -InputObject $provider -EventName OutputDataReceived `
    -Action $outputHandler -MessageData $script:ProviderOutput
$stderrEvent = Register-ObjectEvent -InputObject $provider -EventName ErrorDataReceived `
    -Action $outputHandler -MessageData $script:ProviderOutput
$provider.BeginOutputReadLine()
$provider.BeginErrorReadLine()

function Wait-ProviderOutput {
    param([string]$Pattern, [int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($script:ProviderOutput.ToString() -match $Pattern) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return ($script:ProviderOutput.ToString() -match $Pattern)
}

try {
    Start-Sleep -Seconds 3
    Assert-True (-not $provider.HasExited) 'Provider process is running'

    # -- Test 1: enumeration projects the synthetic tree ---------------------
    $rootEntries = Get-ChildItem $virtRoot -ErrorAction SilentlyContinue
    Assert-True ($rootEntries.Count -gt 0) 'Virtroot enumeration returns entries'
    Assert-True (($rootEntries | Where-Object Name -eq 'AWS').Count -eq 1) 'AWS directory projected'
    Assert-True (($rootEntries | Where-Object Name -eq 'Documents').Count -eq 1) 'Documents directory projected'

    $sshEntries = Get-ChildItem (Join-Path $virtRoot 'SSH Keys') -ErrorAction SilentlyContinue
    Assert-True (($sshEntries | Where-Object Name -eq 'id_rsa').Count -eq 1) 'Nested id_rsa projected'

    # -- Test 2: declared sizes match directory listing ----------------------
    $credentialsInfo = Get-Item (Join-Path $virtRoot 'AWS\credentials')
    Assert-True ($credentialsInfo.Length -eq 116) 'Declared size shown before hydration (credentials = 116)'

    # -- Test 3: reading content fires the read alert and serves content -----
    $credentialsPath = Join-Path $virtRoot 'AWS\credentials'
    $content = Get-Content $credentialsPath -Raw
    Assert-True ($content -match 'AKIAIOSFODNN7EXAMPLE') 'Synthetic credentials content served'
    Assert-True (([Text.Encoding]::UTF8.GetByteCount($content)) -eq 116) 'Served content matches declared size'

    $pemContent = Get-Content (Join-Path $virtRoot 'SSH Keys\id_rsa') -Raw
    Assert-True ($pemContent -match '-----BEGIN RSA PRIVATE KEY-----') 'PEM template served for id_rsa'

    Start-Sleep -Seconds 2

    # -- Test 4: Event Log entries written ------------------------------------
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'; ProviderName = 'PhantomFS'; StartTime = $testStart
    } -ErrorAction SilentlyContinue

    Assert-True (($events | Where-Object Id -eq 1003).Count -ge 1) 'Event 1003 (provider started) logged'
    $readEvents = $events | Where-Object Id -eq 1001
    Assert-True ($readEvents.Count -ge 2) 'Event 1001 (content read) logged for both reads'
    Assert-True (($readEvents | Where-Object { $_.Message -match 'credentials' }).Count -ge 1) `
        'Read event names the accessed file'
    Assert-True (($events | Where-Object Id -eq 1002).Count -ge 1) 'Event 1002 (placeholder created) logged'

    # -- Test 5: auto-cleanup reverts hydrated files, alerts re-fire ----------
    # Wait for the provider to log the revert instead of sleeping a fixed
    # interval. The timer ticks every 30s and only reverts entries older than
    # the configured delay, so the worst case is delay + 30s plus margin.
    $revertTimeout = $CleanupDelaySeconds + 60
    Write-Host ('  waiting for cleanup revert (up to ' + $revertTimeout + 's)...')
    $revertObserved = Wait-ProviderOutput `
        -Pattern '\[CLEANUP\] Reverted to placeholder: AWS\\credentials' `
        -TimeoutSeconds $revertTimeout
    Assert-True $revertObserved 'Cleanup revert logged for AWS\credentials'

    # File must still be visible after the revert (no tombstone).
    Assert-True (Test-Path $credentialsPath) 'File still visible after cleanup revert'

    # Mark the current output length so the post-revert read can be checked in
    # isolation from the pre-revert callbacks captured earlier.
    $outputLengthBeforeReread = $script:ProviderOutput.Length
    $rereadStart = Get-Date
    $rereadContent = Get-Content $credentialsPath -Raw
    Assert-True ($rereadContent -match 'AKIAIOSFODNN7EXAMPLE') 'Content served again after revert'

    # The read must reach the provider again rather than being served from the
    # ProjFS cache. A fresh GetFileData callback after the revert is the direct
    # proof the file was genuinely de-hydrated (this is what PrjDeleteFile fixes;
    # PrjUpdateFileIfNeeded left the cache in place and this callback never fired).
    $freshCallback = Wait-ProviderOutput -Pattern 'GetFileData \[AWS\\credentials\]' -TimeoutSeconds 5
    $newOutput = $script:ProviderOutput.ToString().Substring($outputLengthBeforeReread)
    Assert-True ($freshCallback -and ($newOutput -match 'GetFileData \[AWS\\credentials\]')) `
        'Fresh GetFileData callback fires after revert (file de-hydrated)'

    Start-Sleep -Seconds 2
    $rereadEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'; ProviderName = 'PhantomFS'; StartTime = $rereadStart
    } -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1001 -and $_.Message -match 'credentials' }
    Assert-True ($rereadEvents.Count -ge 1) 'Read alert re-fires after cleanup revert'
}
finally {
    # ---------------------------------------------------------------------
    # Shutdown: send ENTER, then verify the stop event and clean up.
    # ---------------------------------------------------------------------
    if (-not $provider.HasExited) {
        $provider.StandardInput.WriteLine()
        if (-not $provider.WaitForExit(10000)) { $provider.Kill() }
    }

    Unregister-Event -SourceIdentifier $stdoutEvent.Name -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier $stderrEvent.Name -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 1
    $stopEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'; ProviderName = 'PhantomFS'; StartTime = $testStart
    } -ErrorAction SilentlyContinue | Where-Object Id -eq 1004
    Assert-True ($stopEvents.Count -ge 1) 'Event 1004 (provider stopped) logged on shutdown'

    Remove-Item $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ('-' * 50)
Write-Host ('Passed: ' + $script:Passed + '   Failed: ' + $script:Failed)
if ($script:Failed -gt 0) {
    Write-Host ''
    Write-Host 'Provider output (for diagnosis):' -ForegroundColor Yellow
    Write-Host $script:ProviderOutput.ToString()
    exit 1
}
exit 0