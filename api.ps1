# --- CONFIGURATION ---
$DarktraceIP  = "https://192.168.1.100" # Replace with your Darktrace IP/Hostname (no trailing slash)
$PublicToken  = "YOUR_PUBLIC_TOKEN"
$PrivateToken = "YOUR_PRIVATE_TOKEN"
$TempJsonFile = ".\temp_breaches.json"
$OutputFile   = ".\Darktrace_ModelBreaches_Last1Month.csv"
$ChunkDays    = 7 # Pull 7 days at a time to prevent API hangs

# Load .NET JSON serializer to bypass PowerShell 5.1's 4MB ConvertFrom-Json limit
Add-Type -AssemblyName System.Web.Extensions
$JsonSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$JsonSerializer.MaxJsonLength = [int]::MaxValue

$EpochStart = Get-Date -Date "1970-01-01 00:00:00Z"
$FinalEnd   = (Get-Date).ToUniversalTime()
$ChunkStart = $FinalEnd.AddMonths(-1) # Set to 1 month as tested

$AllBreaches = New-Object System.Collections.Generic.List[PSObject]

# Define filterType names Darktrace uses for Destination Hostnames/Domains and Destination IPs
$DomainFilterTypes = @(
    "Connection hostname",
    "Hostname",
    "HTTP host",
    "SSL SNI",
    "SNI",
    "DNS query",
    "URI"
)

$IpFilterTypes = @(
    "Destination IP",
    "Endpoint IP",
    "Dest IP"
)

Write-Host "Starting chunked extraction from $($ChunkStart.ToString('yyyy-MM-dd')) to $($FinalEnd.ToString('yyyy-MM-dd'))..." -ForegroundColor Cyan

while ($ChunkStart -lt $FinalEnd) {
    $ChunkEnd = $ChunkStart.AddDays($ChunkDays)
    if ($ChunkEnd -gt $FinalEnd) { $ChunkEnd = $FinalEnd }

    $StartTimeMs = [math]::Floor(($ChunkStart - $EpochStart).TotalMilliseconds)
    $EndTimeMs   = [math]::Floor(($ChunkEnd - $EpochStart).TotalMilliseconds)

    # Build endpoint & signature for this 7-day window
    $Endpoint   = "/modelbreaches?starttime=$StartTimeMs&endtime=$EndTimeMs"
    $NowUtc     = (Get-Date).ToUniversalTime()
    $DateHeader = $NowUtc.ToString("yyyyMMddTHHmmss")

    $StringToSign = "$Endpoint`n$PublicToken`n$DateHeader"

    $HmacSha1       = New-Object System.Security.Cryptography.HMACSHA1
    $HmacSha1.Key   = [Text.Encoding]::ASCII.GetBytes($PrivateToken)
    $SignatureBytes = $HmacSha1.ComputeHash([Text.Encoding]::ASCII.GetBytes($StringToSign))
    $Signature      = [BitConverter]::ToString($SignatureBytes).Replace("-", "").ToLower()

    $Uri = "$DarktraceIP$Endpoint"

    Write-Host "Fetching window: $($ChunkStart.ToString('yyyy-MM-dd')) -> $($ChunkEnd.ToString('yyyy-MM-dd')) ... " -NoNewline

    if (Test-Path $TempJsonFile) { Remove-Item $TempJsonFile -Force }

    & curl.exe -k -s -S --connect-timeout 15 --max-time 120 `
        -H "DTAPI-Token: $PublicToken" `
        -H "DTAPI-Date: $DateHeader" `
        -H "DTAPI-Signature: $Signature" `
        -H "Accept: application/json" `
        "$Uri" -o $TempJsonFile

    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $TempJsonFile)) {
        Write-Host "FAILED (curl exit code $LASTEXITCODE)" -ForegroundColor Red
        break
    }

    $RawJson = Get-Content -Path $TempJsonFile -Raw -Encoding UTF8

    if ($RawJson -notmatch '^\s*\[') {
        Write-Host "API ERROR!" -ForegroundColor Red
        Write-Error "Unexpected response from Darktrace: $RawJson"
        break
    }

    $ParsedChunk = $JsonSerializer.DeserializeObject($RawJson)
    Write-Host "Retrieved $($ParsedChunk.Count) breaches." -ForegroundColor Green

    foreach ($Breach in $ParsedChunk) {
        $BreachTimeUtc = $EpochStart.AddMilliseconds([double]$Breach["time"]).ToString("yyyy-MM-dd HH:mm:ss")

        # Safely extract Model and Source Device dictionaries
        $ModelObj  = $Breach["model"]
        $ModelThen = if ($ModelObj -and $ModelObj.ContainsKey("then")) { $ModelObj["then"] } else { $ModelObj }
        $DeviceObj = $Breach["device"]

        # Collections to hold unique destination values per breach
        $DestDomains = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
        $DestIPs     = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

        # Walk through triggeredComponents -> triggeredFilters
        $TriggeredComps = $Breach["triggeredComponents"]
        if ($TriggeredComps) {
            foreach ($Comp in $TriggeredComps) {
                $TriggeredFilters = $Comp["triggeredFilters"]
                if ($TriggeredFilters) {
                    foreach ($Filter in $TriggeredFilters) {
                        $FilterType = [string]$Filter["filterType"]
                        $TriggerObj = $Filter["trigger"]
                        $TriggerVal = if ($TriggerObj -and $TriggerObj.ContainsKey("value")) { [string]$TriggerObj["value"] } else { $null }

                        if (-not [string]::IsNullOrWhiteSpace($TriggerVal)) {
                            # Check if filterType matches our domain/hostname filters or wildcard "*hostname*" / "*domain*" / "*SNI*"
                            if ($DomainFilterTypes -contains $FilterType -or $FilterType -match "(?i)(hostname|domain|sni|http host|dns query)") {
                                [void]$DestDomains.Add($TriggerVal)
                            }
                            # Check if filterType matches Destination IP filters
                            elseif ($IpFilterTypes -contains $FilterType -or $FilterType -match "(?i)(destination ip|dest ip|endpoint ip)") {
                                [void]$DestIPs.Add($TriggerVal)
                            }
                        }
                    }
                }
            }
        }

        $AllBreaches.Add([PSCustomObject]@{
            BreachID            = $Breach["pbid"]
            TimeUTC             = $BreachTimeUtc
            ModelName           = if ($ModelThen) { $ModelThen["name"] } else { $null }
            ModelID             = if ($ModelThen) { $ModelThen["pid"] }  else { $null }
            ScorePercent        = [math]::Round(([double]$Breach["score"] * 100), 1)
            SourceDeviceID      = if ($DeviceObj) { $DeviceObj["did"] }       else { $null }
            SourceHostname      = if ($DeviceObj) { $DeviceObj["hostname"] }  else { $null }
            SourceIP            = if ($DeviceObj) { $DeviceObj["ip"] }        else { $null }
            SourceMAC           = if ($DeviceObj) { $DeviceObj["macaddress"]} else { $null }
            DestinationHostname = ($DestDomains -join "; ")
            DestinationIP       = ($DestIPs -join "; ")
            CommentCount        = $Breach["commentCount"]
        })
    }

    # Advance to the next 7-day window
    $ChunkStart = $ChunkEnd.AddMilliseconds(1)
}

if ($AllBreaches.Count -gt 0) {
    $AllBreaches | Sort-Object TimeUTC -Descending | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "`nDone! Exported $($AllBreaches.Count) total breaches to $OutputFile" -ForegroundColor Green
}

if (Test-Path $TempJsonFile) { Remove-Item $TempJsonFile -Force -ErrorAction SilentlyContinue }
