# One-time setup on the OWNER'S OWN Windows machine. PowerShell 5.1 or later.
# Creates a DPAPI-encrypted, owner-local signing key and a 10-minute task.
# Never paste the printed key into ChatGPT, GitHub code or a public channel.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$folder = Join-Path $env:APPDATA 'VynalthShield'
$configPath = Join-Path $folder 'school-beacon.json'
$reportPath = Join-Path $folder 'Report-SchoolBeacon.ps1'
$sourceScript = Join-Path $PSScriptRoot 'Report-SchoolBeacon.ps1'
if (-not (Test-Path -LiteralPath $sourceScript)) {
    throw 'Report-SchoolBeacon.ps1 must be alongside this installer.'
}
if (Test-Path -LiteralPath $configPath) {
    throw ('Existing beacon exists at ' + $configPath + '. Refusing to overwrite an active signing identity.')
}
New-Item -ItemType Directory -Force -Path $folder | Out-Null
$deviceId = [Guid]::NewGuid().ToString('N')
$secret = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($secret) } finally { $rng.Dispose() }
$keyHex = -join ($secret | ForEach-Object { $_.ToString('x2') })
$plainSecure = ConvertTo-SecureString -String $keyHex -AsPlainText -Force
$config = [pscustomobject]@{
    version=1
    ssid='POWIIS_Student'
    deviceId=$deviceId
    keyProtected=ConvertFrom-SecureString -SecureString $plainSecure
}
try {
    $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8
    Copy-Item -LiteralPath $sourceScript -Destination $reportPath -Force
    $taskName = 'Vynalth Shield School Egress Beacon'
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoLogo -NoProfile -NonInteractive -File "'+$reportPath+'"')
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

    Write-Host ''
    Write-Host 'OWNER SETUP REQUIRED - Copy these into CLOUDFLARE WORKER SECRETS / VARIABLES once.'
    Write-Host ('SCHOOL_BEACON_DEVICE_ID = '+$deviceId)
    Write-Host ('SCHOOL_BEACON_SIGNING_KEY = '+$keyHex)
    Write-Host 'Store them privately; never paste into a chat.'
    Write-Host ('Scheduled task: '+$taskName+' every 10 minutes when you are logged in.')
    Write-Host 'The task reports ONLY on the exact POWIIS_Student SSID with no detected VPN route.'
    Write-Host 'No school IP can be auto-blocked until the Cloudflare Worker, IP List and WAF are configured.'
} finally {
    [Array]::Clear($secret,0,$secret.Length)
    $keyHex=$null
}
