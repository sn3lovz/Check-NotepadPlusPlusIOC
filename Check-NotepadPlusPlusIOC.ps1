#Requires -Version 5.1
<#
.SYNOPSIS
    Checks for indicators of compromise related to the Notepad++ supply chain attack.
.DESCRIPTION
    Scans the local machine for file system artifacts, running processes, and network
    connections associated with the Notepad++ supply chain attack documented at:
    https://securelist.com/notepad-supply-chain-attack/118708/
.OUTPUTS
    PSCustomObject[] - Table of check results with Status (CLEAN/FOUND/WARNING) and Details.
.EXAMPLE
    .\Check-NotepadPlusPlusIOC.ps1
#>

[CmdletBinding()]
param()

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Result {
    param(
        [string]$Check,
        [string]$Status,
        [string]$Details
    )
    $results.Add([PSCustomObject]@{
        Check   = $Check
        Status  = $Status
        Details = $Details
    })
}

# --- File system checks ---

$malwareDirs = @(
    @{ Name = '%APPDATA%\ProShow\';        Path = "$env:APPDATA\ProShow" }
    @{ Name = '%APPDATA%\Adobe\Scripts\';  Path = "$env:APPDATA\Adobe\Scripts" }
    @{ Name = '%APPDATA%\Bluetooth\';      Path = "$env:APPDATA\Bluetooth" }
)

foreach ($dir in $malwareDirs) {
    if (Test-Path -Path $dir.Path) {
        $files = Get-ChildItem -Path $dir.Path -Recurse -Force -ErrorAction SilentlyContinue |
                 Select-Object -ExpandProperty FullName
        Add-Result -Check "$($dir.Name) directory" -Status 'FOUND' `
                   -Details ("Contains: " + ($files -join ', '))
    } else {
        Add-Result -Check "$($dir.Name) directory" -Status 'CLEAN' -Details 'Not found'
    }
}

$malwareFiles = @(
    @{ Name = 'Payload: load';             Path = "$env:APPDATA\ProShow\load" }
    @{ Name = 'Config: alien.ini';         Path = "$env:APPDATA\Adobe\Scripts\alien.ini" }
    @{ Name = 'Backdoor: BluetoothService';Path = "$env:APPDATA\Bluetooth\BluetoothService" }
    @{ Name = 'NSIS temp: ns.tmp';         Path = "$env:LOCALAPPDATA\Temp\ns.tmp" }
    @{ Name = 'Recon output: 1.txt';       Path = "$env:LOCALAPPDATA\Temp\1.txt" }
    @{ Name = 'Recon output: a.txt';       Path = "$env:LOCALAPPDATA\Temp\a.txt" }
)

foreach ($file in $malwareFiles) {
    if (Test-Path -Path $file.Path) {
        $info = Get-Item -Path $file.Path -Force -ErrorAction SilentlyContinue
        Add-Result -Check $file.Name -Status 'FOUND' `
                   -Details "Size: $($info.Length) bytes, Modified: $($info.LastWriteTime)"
    } else {
        Add-Result -Check $file.Name -Status 'CLEAN' -Details 'Not found'
    }
}

# --- Process checks ---

$suspiciousProcesses = @('ProShow', 'GUP', 'BluetoothService')
$runningProcs = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.ProcessName -match ($suspiciousProcesses -join '|') }

if ($runningProcs) {
    $procNames = ($runningProcs | Select-Object -ExpandProperty ProcessName -Unique) -join ', '
    Add-Result -Check 'Suspicious processes' -Status 'FOUND' -Details "Running: $procNames"
} else {
    Add-Result -Check 'Suspicious processes' -Status 'CLEAN' -Details 'None running'
}

# --- Network connection checks ---

$c2Ips = @(
    '45.76.155.202'
    '45.32.144.255'
    '95.179.213.0'
    '45.77.31.210'
    '59.110.7.32'
    '124.222.137.114'
)

$c2Domains = @(
    'skycloudcenter.com'
    'wiresguard.com'
    'cdncheck.it.com'
    'safe-dns.it.com'
    'self-dns.it.com'
)

try {
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue

    $matchedIps = $connections |
                  Where-Object { $c2Ips -contains $_.RemoteAddress } |
                  Select-Object -ExpandProperty RemoteAddress -Unique

    if ($matchedIps) {
        Add-Result -Check 'Connections to C2 IPs' -Status 'FOUND' `
                   -Details "Connected to: $($matchedIps -join ', ')"
    } else {
        Add-Result -Check 'Connections to C2 IPs' -Status 'CLEAN' -Details 'None detected'
    }
} catch {
    Add-Result -Check 'Connections to C2 IPs' -Status 'WARNING' `
               -Details 'Could not query network connections (requires elevation)'
}

# DNS cache check for C2 domains
try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    $matchedDns = $dnsCache |
                  Where-Object { foreach ($d in $c2Domains) { if ($_.Entry -like "*$d*") { return $true } } return $false }

    if ($matchedDns) {
        $found = ($matchedDns | Select-Object -ExpandProperty Entry -Unique) -join ', '
        Add-Result -Check 'DNS cache: C2 domains' -Status 'FOUND' -Details "Resolved: $found"
    } else {
        Add-Result -Check 'DNS cache: C2 domains' -Status 'CLEAN' -Details 'None in cache'
    }
} catch {
    Add-Result -Check 'DNS cache: C2 domains' -Status 'WARNING' `
               -Details 'Could not query DNS cache'
}

# --- Notepad++ plugins directory ---

$nppPluginPath = "$env:APPDATA\Notepad++\plugins"
if (Test-Path -Path $nppPluginPath) {
    $pluginDirs = Get-ChildItem -Path $nppPluginPath -Directory -Force -ErrorAction SilentlyContinue |
                  Select-Object -ExpandProperty Name
    $nonDefault = $pluginDirs | Where-Object { $_ -ne 'config' }
    if ($nonDefault) {
        Add-Result -Check 'Notepad++ plugins' -Status 'WARNING' `
                   -Details "Non-default folders: $($nonDefault -join ', ')"
    } else {
        Add-Result -Check 'Notepad++ plugins' -Status 'CLEAN' -Details 'Only default content'
    }
} else {
    Add-Result -Check 'Notepad++ plugins' -Status 'CLEAN' -Details 'Notepad++ not installed or no plugins dir'
}

# --- SHA1 hash check of known malicious files ---

$knownSha1 = @(
    '8e6e505438c21f3d281e1cc257abdbf7223b7f5a'
    '90e677d7ff5844407b9c073e3b7e896e078e11cd'
    '573549869e84544e3ef253bdba79851dcde4963a'
    '13179c8f19fbf3d8473c49983a199e6cb4f318f0'
    '4c9aac447bf732acc97992290aa7a187b967ee2c'
    '821c0cafb2aab0f063ef7e313f64313fc81d46cd'
    'd7ffd7b588880cf61b603346a3557e7cce648c93'
    '06a6a5a39193075734a32e0235bde0e979c27228'
    '9c3ba38890ed984a25abb6a094b5dbf052f22fa7'
    'ca4b6fe0c69472cd3d63b212eb805b7f65710d33'
    '0d0f315fd8cf408a483f8e2dd1e69422629ed9fd'
    '2a476cfb85fbf012fdbe63a37642c11afa5cf020'
    '21a942273c14e4b9d3faa58e4de1fd4d5014a1ed'
    '7e0790226ea461bcc9ecd4be3c315ace41e1c122'
    'f7910d943a013eede24ac89d6388c1b98f8b3717'
    '94dffa9de5b665dc51bc36e2693b8a3a0a4cc6b8'
    '73d9d0139eaf89b7df34ceeb60e5f8c7cd2463bf'
    'bd4915b3597942d88f319740a9b803cc51585c4a'
    'c68d09dd50e357fd3de17a70b7724f8949441d77'
    '813ace987a61af909c053607635489ee984534f4'
    '9fbf2195dee991b1e5a727fd51391dcc2d7a4b16'
    '07d2a01e1dc94d59d5ca3bdf0c7848553ae91a51'
    '3090ecf034337857f786084fb14e63354e271c5d'
    'd0662eadbe5ba92acbd3485d8187112543bcfbf5'
    '9c0eff4deeb626730ad6a05c85eb138df48372ce'
)

$hashCheckPaths = @(
    "$env:APPDATA\ProShow"
    "$env:APPDATA\Adobe\Scripts"
    "$env:APPDATA\Bluetooth"
)

$hashMatches = [System.Collections.Generic.List[string]]::new()
foreach ($dir in $hashCheckPaths) {
    if (Test-Path -Path $dir) {
        Get-ChildItem -Path $dir -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash
            if ($hash -and $knownSha1 -contains $hash.ToLower()) {
                $hashMatches.Add("$($_.FullName) [$hash]")
            }
        }
    }
}

if ($hashMatches.Count -gt 0) {
    Add-Result -Check 'SHA1 hash matches' -Status 'FOUND' `
               -Details ($hashMatches -join '; ')
} else {
    Add-Result -Check 'SHA1 hash matches' -Status 'CLEAN' `
               -Details 'No known malicious hashes found'
}

# --- Output ---

Write-Host ''
Write-Host "=== Notepad++ Supply Chain Attack IOC Check ===" -ForegroundColor Cyan
Write-Host "Machine : $env:COMPUTERNAME"
Write-Host "User    : $env:USERNAME"
Write-Host "Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Reference: https://securelist.com/notepad-supply-chain-attack/118708/"
Write-Host ''

$results | ForEach-Object {
    $color = switch ($_.Status) {
        'CLEAN'   { 'Green' }
        'FOUND'   { 'Red' }
        'WARNING' { 'Yellow' }
    }
    $statusTag = "[$($_.Status)]"
    Write-Host ("{0,-40} {1,-10} {2}" -f $_.Check, $statusTag, $_.Details) -ForegroundColor $color
}

Write-Host ''
$foundCount = ($results | Where-Object { $_.Status -eq 'FOUND' }).Count
if ($foundCount -gt 0) {
    Write-Host "RESULT: $foundCount indicator(s) of compromise detected. Investigate immediately." -ForegroundColor Red
} else {
    Write-Host 'RESULT: No indicators of compromise detected.' -ForegroundColor Green
}
Write-Host ''
