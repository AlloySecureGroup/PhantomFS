<#
.SYNOPSIS
    Provisions and launches multiple PhantomFS honeypot instances, each with
    its own industry-flavored synthetic file set.

.DESCRIPTION
    PhantomFS.exe reads PhantomFS.exe.config from a path derived from its own
    entry-assembly location (entryAssembly.Location + ".config"). There is no
    supported "--config" style override, so the only way to run several
    differently-configured instances is to give each one its own copy of the
    exe sitting next to its own config. This script does exactly that:

      1. Creates one folder per instance under $InstanceRoot.
      2. Copies the master PhantomFS.exe into each folder.
      3. Writes a per-instance PhantomFS.exe.config next to that copy.
      4. Launches each copy with its own --virtroot, non-interactively.
      5. Tracks PIDs in a state file so -Stop can shut everything down later.

.PARAMETER MasterExe
    Path to the compiled PhantomFS.exe (built via csc.exe).

.PARAMETER InstanceRoot
    Where per-instance working folders (exe copy + config) are created.

.PARAMETER VirtRootBase
    Where each instance's virtual honeypot directory is projected.

.PARAMETER Stop
    Stop all tracked instances and remove their virtroots/instance folders.

.EXAMPLE
    .\Start-PhantomFSFleet.ps1 -MasterExe C:\Build\PhantomFS.exe

.EXAMPLE
    .\Start-PhantomFSFleet.ps1 -Stop
#>

[CmdletBinding()]
param(
    [string]$MasterExe     = 'C:\Build\PhantomFS.exe',
    [string]$InstanceRoot  = 'C:\PhantomFS\Instances',
    [string]$VirtRootBase  = 'C:\PhantomFS\Virtual',
    [string]$SyntheticYamlPath = '',
    [switch]$Stop
)

$ErrorActionPreference = 'Stop'
$StateFile = Join-Path $InstanceRoot 'fleet-state.json'

# =============================================================================
# Shared content used across most industry configs
# =============================================================================

$CommonTemplates = @'
    <template name="credentials"><![CDATA[
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
]]></template>

    <template name="id_rsa"     type="pem" pemLabel="RSA PRIVATE KEY"     />
    <template name="id_ed25519" type="pem" pemLabel="OPENSSH PRIVATE KEY" />

    <template extension=".pem" type="pem" pemLabel="PRIVATE KEY" />

    <template extension=".json"><![CDATA[
{
  "synthetic": true,
  "generator": "PhantomFS",
  "note": "This is a honeypot file. Access has been logged."
}
]]></template>

    <template extension=".csv"><![CDATA[
id,name,email,department,access_level
1,admin,admin@example.com,IT,superadmin
2,deploy,deploy@example.com,Engineering,admin
3,backup,backup@example.com,Operations,read-only
]]></template>

    <template extension=".txt"><![CDATA[
CONFIDENTIAL
This file contains sensitive information.
Access is monitored and logged.
Authorised personnel only.
]]></template>
'@

# =============================================================================
# Per-industry synthetic file trees (kept short - extend as needed)
# =============================================================================

$Industries = @(
    [pscustomobject]@{
        Name        = 'Finance'
        VirtRoot    = Join-Path $VirtRootBase 'Finance'
        FileList    = @'
\AWS,true,0,1743942586
\AWS\credentials,false,116,1741508986
\Documents,true,0,1744586986
\Documents\Q4_Financial_Report_2024.pdf,false,8192,1744586986
\Documents\Executive_Compensation_2024.xlsx,false,3840,1742354986
\SSH Keys,true,0,1751527786
\SSH Keys\id_rsa,false,1675,1738927786
\Wire_Transfer_Approvals.xlsx,false,2200,1745674186
'@
        Templates   = @'
    <template extension=".pdf"><![CDATA[
%PDF-1.4
1 0 obj
<</Type /Catalog /Pages 2 0 R>>
endobj
2 0 obj
<</Type /Pages /Kids [3 0 R] /Count 1>>
endobj
3 0 obj
<</Type /Page /MediaBox [0 0 612 792] /Parent 2 0 R
/Resources <</Font <</F1 <</Type /Font /Subtype /Type1 /BaseFont /Helvetica>>>>>>
/Contents 4 0 R>>
endobj
4 0 obj
<</Length 96>>
stream
BT /F1 20 Tf 72 700 Td (CONFIDENTIAL - FINANCE) Tj ET
endstream
endobj
trailer
<</Size 5 /Root 1 0 R>>
%%EOF
]]></template>

    <template extension=".xlsx"><![CDATA[
<html><body>
<h2 style="color:#C00000">CONFIDENTIAL - FINANCE - AUTHORIZED ACCESS ONLY</h2>
<table border="1">
<tr><th>Account</th><th>Balance</th><th>Owner</th></tr>
<tr><td>OPS-4471</td><td>$4,820,113</td><td>Treasury</td></tr>
<tr><td>PAYROLL-0092</td><td>$918,442</td><td>HR/Finance</td></tr>
</table>
</body></html>
]]></template>
'@
    },
    [pscustomobject]@{
        Name        = 'Healthcare'
        VirtRoot    = Join-Path $VirtRootBase 'Healthcare'
        FileList    = @'
\EHR Exports,true,0,1743942586
\EHR Exports\patient_export_2024Q4.csv,false,15400,1744586986
\EHR Exports\phi_backup.json,false,9800,1741508986
\Documents,true,0,1739636986
\Documents\HIPAA_Audit_Findings.docx,false,4800,1741508986
\SSH Keys,true,0,1751527786
\SSH Keys\id_ed25519,false,411,1740680986
\Insurance_Claims_Master.csv,false,26000,1745674186
'@
        Templates   = @'
    <template name="patient_export_2024Q4.csv"><![CDATA[
patient_id,name,dob,diagnosis_code,provider,insurance_id
100234,REDACTED,1978-03-11,E11.9,Dr. Patel,INS-88213
100235,REDACTED,1990-07-22,I10,Dr. Nguyen,INS-11029
]]></template>

    <template name="phi_backup.json"><![CDATA[
{
  "synthetic": true,
  "note": "Honeypot PHI export - access logged",
  "record_count": 48210
}
]]></template>

    <template extension=".docx"><![CDATA[
<!DOCTYPE html><html><head><title>CONFIDENTIAL</title></head>
<body>
<p style="color:#C00000"><b>CONFIDENTIAL - PHI - HIPAA PROTECTED</b></p>
<h1>Audit Findings</h1>
<p>This document is restricted to Compliance and Legal. Access is monitored.</p>
</body></html>
]]></template>
'@
    },
    [pscustomobject]@{
        Name        = 'Legal'
        VirtRoot    = Join-Path $VirtRootBase 'Legal'
        FileList    = @'
\Client Files,true,0,1743942586
\Client Files\Settlement_Agreement_Draft.docx,false,5400,1744586986
\Client Files\Litigation_Hold_Notice.pdf,false,3200,1741508986
\API Keys,true,0,1744586986
\API Keys\docusign_api_keys.txt,false,260,1748708986
\SSH Keys,true,0,1751527786
\SSH Keys\deploy_key.pem,false,1704,1742354986
\Privileged_Communications_Log.xlsx,false,3100,1745674186
'@
        Templates   = @'
    <template name="docusign_api_keys.txt"><![CDATA[
# DocuSign API - Production
Integration Key: EXAMPLE-1234-5678-90ab-cdefEXAMPLE
User ID:         EXAMPLE-abcd-1234-efgh-5678EXAMPLE
Account ID:      EXAMPLE-9988-7766-5544-3322EXAMPLE
]]></template>

    <template name="deploy_key.pem" type="pem" pemLabel="RSA PRIVATE KEY" />

    <template extension=".docx"><![CDATA[
<!DOCTYPE html><html><head><title>CONFIDENTIAL</title></head>
<body>
<p style="color:#C00000"><b>ATTORNEY-CLIENT PRIVILEGED - DO NOT DISTRIBUTE</b></p>
<h1>Settlement Agreement (Draft)</h1>
<p>Prepared for internal review only. Unauthorised access is logged and reported.</p>
</body></html>
]]></template>
'@
    },
    [pscustomobject]@{
        Name        = 'SaaS_DevOps'
        VirtRoot    = Join-Path $VirtRootBase 'SaaS_DevOps'
        FileList    = @'
\AWS,true,0,1743942586
\AWS\credentials,false,116,1741508986
\AWS\iam_access_keys.csv,false,198,1744586986
\API Keys,true,0,1744586986
\API Keys\api_keys.json,false,847,1748708986
\API Keys\github_pat.txt,false,93,1745674186
\API Keys\stripe_keys.txt,false,312,1749252586
\SSH Keys,true,0,1751527786
\SSH Keys\id_rsa,false,1675,1738927786
\SSH Keys\id_ed25519,false,411,1740680986
\.env.production,false,640,1749252586
'@
        Templates   = @'
    <template name="api_keys.json"><![CDATA[
{
  "openai":   { "api_key": "sk-EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz1234" },
  "sendgrid": { "api_key": "SG.EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz" },
  "stripe":   { "secret_key": "sk_live_EXAMPLE1234567890abcdefghijklmnopqrstuvwx" }
}
]]></template>

    <template name="github_pat.txt"><![CDATA[
ghp_EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz12
Scopes: repo, workflow, read:org
]]></template>

    <template name=".env.production"><![CDATA[
DATABASE_URL=postgres://admin:EXAMPLEPASSWORD@prod-db.internal:5432/app
REDIS_URL=redis://:EXAMPLEPASSWORD@prod-cache.internal:6379
JWT_SECRET=EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz
STRIPE_SECRET_KEY=sk_live_EXAMPLE1234567890abcdefghijklmnopqrstuvwx
]]></template>
'@
    },
    [pscustomobject]@{
        Name        = 'Retail'
        VirtRoot    = Join-Path $VirtRootBase 'Retail'
        FileList    = @'
\API Keys,true,0,1744586986
\API Keys\payment_gateway_keys.txt,false,340,1749252586
\Documents,true,0,1739636986
\Documents\Vendor_Pricing_Master.xlsx,false,5200,1742354986
\Documents\Customer_Loyalty_Export.csv,false,18800,1744586986
\SSH Keys,true,0,1751527786
\SSH Keys\id_rsa,false,1675,1738927786
\POS_System_Config.json,false,980,1745674186
'@
        Templates   = @'
    <template name="payment_gateway_keys.txt"><![CDATA[
# Payment Gateway - Production
Merchant ID: EXAMPLE-MID-778211
API Key:     EXAMPLE1234567890abcdefghijklmnop
API Secret:  EXAMPLE1234567890abcdefghijklmnopqrstuv
]]></template>

    <template name="Customer_Loyalty_Export.csv"><![CDATA[
customer_id,name,email,loyalty_tier,card_last4
551029,REDACTED,customer1@example.com,Gold,4412
551030,REDACTED,customer2@example.com,Silver,7790
]]></template>

    <template extension=".xlsx"><![CDATA[
<html><body>
<h2 style="color:#C00000">CONFIDENTIAL - VENDOR PRICING</h2>
<table border="1">
<tr><th>Vendor</th><th>SKU</th><th>Cost</th><th>Margin %</th></tr>
<tr><td>Acme Supply</td><td>SKU-8821</td><td>$4.10</td><td>62%</td></tr>
</table>
</body></html>
]]></template>
'@
    }
)

# =============================================================================
# Config template - shared settings block, per-industry file list/templates
# =============================================================================

function New-PhantomConfigXml {
    param(
        [string]$VirtRoot,
        [string]$FileListXml,
        [string]$TemplatesXml,
        [string]$SyntheticYamlPath
    )

    $yamlPathElementValue = if ([string]::IsNullOrWhiteSpace($SyntheticYamlPath)) { '' } else { $SyntheticYamlPath }

    return @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <settings>
    <enableEventLog>true</enableEventLog>
    <enableToast>true</enableToast>
    <alertOnOpen>true</alertOnOpen>
    <alertOnRead>true</alertOnRead>
    <toastCooldownSeconds>15</toastCooldownSeconds>
    <verbose>false</verbose>
    <virtRoot>$VirtRoot</virtRoot>
    <sourceRoot></sourceRoot>
    <syntheticOnly>true</syntheticOnly>
    <syntheticYamlPath>$yamlPathElementValue</syntheticYamlPath>
    <autoCleanupEnabled>true</autoCleanupEnabled>
    <autoCleanupDelaySeconds>300</autoCleanupDelaySeconds>
    <resolveRemoteIPs>true</resolveRemoteIPs>
  </settings>

  <syntheticFileList><![CDATA[
$FileListXml
]]></syntheticFileList>

  <syntheticTemplates>
$TemplatesXml
$CommonTemplates
  </syntheticTemplates>
</configuration>
"@
}

# =============================================================================
# Start
# =============================================================================

function Start-Fleet {
    if (-not (Test-Path $MasterExe)) {
        throw "MasterExe not found: $MasterExe. Build PhantomFS.exe first, or pass -MasterExe."
    }

    if (-not [string]::IsNullOrWhiteSpace($SyntheticYamlPath) -and -not (Test-Path $SyntheticYamlPath)) {
        throw "SyntheticYamlPath not found: $SyntheticYamlPath"
    }

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run elevated (PhantomFS requires Administrator)."
    }

    New-Item -ItemType Directory -Force -Path $InstanceRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $VirtRootBase | Out-Null

    $tracked = @()

    foreach ($industry in $Industries) {
        $instanceDir = Join-Path $InstanceRoot $industry.Name
        New-Item -ItemType Directory -Force -Path $instanceDir | Out-Null

        $exeCopyPath    = Join-Path $instanceDir 'PhantomFS.exe'
        $configCopyPath = "$exeCopyPath.config"
        $instanceYamlPath = ''

        Copy-Item -Path $MasterExe -Destination $exeCopyPath -Force

        if (-not [string]::IsNullOrWhiteSpace($SyntheticYamlPath)) {
            $instanceYamlPath = Join-Path $instanceDir 'synthetic-data.yml'
            Copy-Item -Path $SyntheticYamlPath -Destination $instanceYamlPath -Force
        }

        $configXml = New-PhantomConfigXml -VirtRoot $industry.VirtRoot `
                                           -FileListXml $industry.FileList `
                                           -TemplatesXml $industry.Templates `
                                           -SyntheticYamlPath $instanceYamlPath
        Set-Content -Path $configCopyPath -Value $configXml -Encoding UTF8

        Write-Host "  [$($industry.Name)] exe : $exeCopyPath"
        Write-Host "  [$($industry.Name)] cfg : $configCopyPath"
        Write-Host "  [$($industry.Name)] root: $($industry.VirtRoot)"
        if (-not [string]::IsNullOrWhiteSpace($instanceYamlPath)) {
            Write-Host "  [$($industry.Name)] yaml: $instanceYamlPath"
        }

        $arguments = @('--virtroot', "`"$($industry.VirtRoot)`"", '--syntheticonly', '--service')
        if (-not [string]::IsNullOrWhiteSpace($instanceYamlPath)) {
            $arguments += @('--syntheticyaml', "`"$instanceYamlPath`"")
        }

        $proc = Start-Process -FilePath $exeCopyPath `
                               -ArgumentList $arguments `
                               -WorkingDirectory $instanceDir `
                               -WindowStyle Hidden `
                               -PassThru

        Start-Sleep -Milliseconds 500   # stagger EventLog source registration

        $tracked += [pscustomobject]@{
            Name        = $industry.Name
            Pid         = $proc.Id
            InstanceDir = $instanceDir
            VirtRoot    = $industry.VirtRoot
            StartedAt   = (Get-Date).ToString('o')
        }

        Write-Host "  [$($industry.Name)] started, PID $($proc.Id)`n"
    }

    $tracked | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8
    Write-Host "Fleet state saved to $StateFile"
    Write-Host "$($tracked.Count) instance(s) running. Use -Stop to shut them down."
}

# =============================================================================
# Stop
# =============================================================================

function Stop-Fleet {
    if (-not (Test-Path $StateFile)) {
        Write-Warning "No state file at $StateFile - nothing to stop."
        return
    }

    $tracked = Get-Content $StateFile -Raw | ConvertFrom-Json

    foreach ($entry in $tracked) {
        $process = Get-Process -Id $entry.Pid -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "  [$($entry.Name)] stopping PID $($entry.Pid) ..."
            # Stop-Process is a hard kill (TerminateProcess). PhantomFS registers
            # ProcessExit for graceful revert-and-remove, but that handler only
            # fires on a normal exit path, not a forced kill - so the virtroot
            # is removed manually below as a fallback.
            Stop-Process -Id $entry.Pid -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 300
        }
        else {
            Write-Host "  [$($entry.Name)] PID $($entry.Pid) already gone."
        }

        if (Test-Path $entry.VirtRoot) {
            try {
                Remove-Item -Path $entry.VirtRoot -Recurse -Force -ErrorAction Stop
                Write-Host "  [$($entry.Name)] virtroot removed: $($entry.VirtRoot)"
            }
            catch {
                Write-Warning "  [$($entry.Name)] could not remove virtroot: $($_.Exception.Message)"
            }
        }
    }

    Remove-Item -Path $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "Fleet stopped."
}

# =============================================================================
# Entry point
# =============================================================================

if ($Stop) {
    Stop-Fleet
}
else {
    Start-Fleet
}
