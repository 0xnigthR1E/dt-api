# --- CONFIGURATION ---
$DarktraceIP  = "https://192.168.1.100" # Replace with your Darktrace IP/Hostname (no trailing slash)
$PublicToken  = "YOUR_PUBLIC_TOKEN"
$PrivateToken = "YOUR_PRIVATE_TOKEN"
$TempJsonFile = ".\temp_breaches.json"
$OutputFile   = ".\Darktrace_ModelBreaches_Last3Months.csv"

# 1. Calculate Epoch Timestamps (in milliseconds) for the past 3 months
$EpochStart     = Get-Date -Date "1970-01-01 00:00:00Z"
$Now            = (Get-Date).ToUniversalTime()
$ThreeMonthsAgo = $Now.AddMonths(-3)

$StartTimeMs = [math]::Floor(($ThreeMonthsAgo - $EpochStart).TotalMilliseconds)
$EndTimeMs   = [math]::Floor(($Now - $EpochStart).TotalMilliseconds)

# 2. Build API Query and HMAC-SHA1 Signature
$Endpoint   = "/modelbreaches?starttime=$StartTimeMs&endtime=$EndTimeMs"
$DateHeader = $Now.ToString("yyyyMMddTHHmmss")

$StringToSign = "$Endpoint`n$PublicToken`n$DateHeader"

$HmacSha1       = New-Object System.Security.Cryptography.HMACSHA1
$HmacSha1.Key   = [Text.Encoding]::ASCII.GetBytes($PrivateToken)
$SignatureBytes = $HmacSha1.ComputeHash([Text.Encoding]::ASCII.GetBytes($StringToSign))
$Signature      = [BitConverter]::ToString($SignatureBytes).Replace("-", "").ToLower()

$Uri = "$DarktraceIP$Endpoint"

# 3. Execute Request via curl.exe
# -k : Insecure (skips self-signed cert validation)
# -s : Silent mode (hides progress bar)
# -S : Show errors if it fails
# -o : Write output directly to a file (avoids PowerShell console encoding/buffer issues)
Write-Host "Fetching data from Darktrace using curl.exe..." -ForegroundColor Cyan

& curl.exe -k -s -S `
    -H "DTAPI-Token: $PublicToken" `
    -H "DTAPI-Date: $DateHeader" `
    -H "DTAPI-Signature: $Signature" `
    -H "Accept: application/json" `
    "$Uri" -o $TempJsonFile

# Verify curl.exe succeeded and the file exists
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $TempJsonFile)) {
    Write-Error "curl.exe failed with exit code $LASTEXITCODE."
    return
}

# 4. Read JSON and Transform to CSV in PowerShell
Write-Host "Parsing JSON and generating CSV..." -ForegroundColor Cyan

try {
    $RawJson  = Get-Content -Path $TempJsonFile -Raw -Encoding UTF8
    $Response = $RawJson | ConvertFrom-Json

    $CsvData = foreach ($Breach in $Response) {
        $BreachTimeUtc = $EpochStart.AddMilliseconds($Breach.time).ToString("yyyy-MM-dd HH:mm:ss")

        $ModelName = if ($Breach.model.then.name) { $Breach.model.then.name } else { $Breach.model.name }
        $ModelPid  = if ($Breach.model.then.pid)  { $Breach.model.then.pid }  else { $Breach.model.pid }

        [PSCustomObject]@{
            BreachID     = $Breach.pbid
            TimeUTC      = $BreachTimeUtc
            ModelName    = $ModelName
            ModelID      = $ModelPid
            ScorePercent = [math]::Round(($Breach.score * 100), 1)
            DeviceID     = $Breach.device.did
            Hostname     = $Breach.device.hostname
            IPAddress    = $Breach.device.ip
            MACAddress   = $Breach.device.macaddress
            DeviceLabel  = $Breach.device.typelabel
            CommentCount = $Breach.commentCount
        }
    }

    $CsvData | Sort-Object TimeUTC -Descending | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Successfully exported $($CsvData.Count) breaches to $OutputFile" -ForegroundColor Green

    # Clean up temporary JSON file
    Remove-Item -Path $TempJsonFile -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Error "Failed to parse JSON response. Check $TempJsonFile to see if the API returned an HTML/text error message. Details: $($_.Exception.Message)"
}
