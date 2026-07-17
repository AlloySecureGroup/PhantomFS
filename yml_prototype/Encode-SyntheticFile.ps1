<#
.SYNOPSIS
    Gzip-compresses and base64-encodes a file, and outputs both the "files:"
    and "templates:" entries ready to paste into synthetic-data.yml.

.PARAMETER Path
    Local file to encode.

.PARAMETER VirtualPath
    Virtual path to project inside the honeypot (e.g. "Documents/logo.png").
    Defaults to just the file name (placed at the virtual root).

.PARAMETER Timestamp
    Unix timestamp for the files: entry. Defaults to the file's last-write
    time.

.PARAMETER NoGzip
    Skip gzip compression - produces "type: base64" instead of
    "type: base64gzip". Fine for small files.

.PARAMETER OutFile
    Write the snippet straight to this file instead of the console. Use this
    for anything but the smallest files - a long base64 blob printed to a
    terminal can get soft-wrapped or truncated by the console/scrollback,
    silently corrupting the payload. Writing to a file skips the terminal
    entirely, so copy the snippet from that file, not from console output.

.EXAMPLE
    .\Encode-SyntheticFile.ps1 -Path C:\Temp\honeybadger.png -VirtualPath "Documents/honeybadger.png"

.EXAMPLE
    .\Encode-SyntheticFile.ps1 -Path C:\Temp\HelloWorld.exe -VirtualPath "Documents/HelloWorld.exe" -OutFile .\HelloWorld_snippet.yml

.EXAMPLE
    .\Encode-SyntheticFile.ps1 -Path C:\Temp\logo.png -NoGzip
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$VirtualPath,

    [long]$Timestamp,

    [switch]$NoGzip,

    [string]$OutFile
)

# Above this many base64 characters, a console can plausibly soft-wrap or
# truncate the blob (this is exactly what corrupted a HelloWorld.exe payload
# copy-pasted from a terminal in testing - it came out 9 bytes short with a
# failed CRC check). Just a heads-up threshold, not a hard limit.
$WrapRiskThresholdChars = 1500

if (-not (Test-Path $Path)) {
    Write-Error "File not found: $Path"
    exit 1
}

$fileInfo = Get-Item $Path
$rawBytes = [System.IO.File]::ReadAllBytes($Path)

if (-not $VirtualPath) {
    $VirtualPath = $fileInfo.Name
}
$VirtualPath = $VirtualPath -replace '\\', '/'
$templateName = Split-Path $VirtualPath -Leaf

if (-not $Timestamp) {
    $Timestamp = [long]([DateTimeOffset]$fileInfo.LastWriteTimeUtc).ToUnixTimeSeconds()
}

if ($NoGzip) {
    $outputBytes = $rawBytes
    $templateType = "base64"
} else {
    $memoryStream = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GZipStream($memoryStream, [System.IO.Compression.CompressionMode]::Compress)
    $gzipStream.Write($rawBytes, 0, $rawBytes.Length)
    $gzipStream.Close()
    $outputBytes = $memoryStream.ToArray()
    $templateType = "base64gzip"
}

$base64 = [System.Convert]::ToBase64String($outputBytes)

# Wrap to 76 chars per line, indented 6 spaces to sit under "content: |"
$wrapped = ($base64 -split '(?<=\G.{76})' | ForEach-Object { "      $_" }) -join "`n"

$snippet = @"
  - path: $VirtualPath
    directory: false
    size: $($rawBytes.Length)
    timestamp: $Timestamp

templates:
  # -- $templateName --
  - name: $templateName
    type: $templateType
    content: |
$wrapped
"@

Write-Host ""
Write-Host "File           : $Path"
Write-Host "Virtual path   : $VirtualPath"
Write-Host "Original size  : $($rawBytes.Length) bytes"
if (-not $NoGzip) {
    Write-Host "Gzip size      : $($outputBytes.Length) bytes"
}
Write-Host "Template type  : $templateType"
Write-Host "Base64 length  : $($base64.Length) chars"

if ($OutFile) {
    # Written directly from memory to disk as plain ASCII - the terminal is
    # never involved, so there is no wrapping/truncation risk here.
    [System.IO.File]::WriteAllText($OutFile, $snippet, [System.Text.Encoding]::ASCII)
    Write-Host ""
    Write-Host "Wrote snippet to: $OutFile"
    Write-Host "Copy the snippet FROM THAT FILE into synthetic-data.yml - don't retype or"
    Write-Host "re-copy it via the console."
} else {
    if ($base64.Length -gt $WrapRiskThresholdChars) {
        Write-Host ""
        Write-Warning "Base64 payload is $($base64.Length) chars - printing this to a terminal risks silent wrapping/truncation. Re-run with -OutFile <path> instead."
    }
    Write-Host ""
    Write-Host "Paste into synthetic-data.yml:"
    Write-Host "---------------------------------------------------"
    Write-Host $snippet
    Write-Host "---------------------------------------------------"
}
