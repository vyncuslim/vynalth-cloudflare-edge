# School Beacon reporter: Windows PowerShell 5.1+, user-owned device only.
# Config contains a per-user DPAPI-encrypted HMAC key, never a plaintext secret.
# Run via the scheduled task provisioned by Install-SchoolBeacon.ps1.
[CmdletBinding()]
param(
  [string]$ConfigPath = "$env:APPDATA\VynalthShield\school-beacon.json"
)
$ErrorActionPreference = 'Stop'
$endpoint = 'https://vynalthai.com/__shield/campus-beacon'

try {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return }
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ($config.ssid -cne 'POWIIS_Student') { throw 'Unapproved configured SSID.' }
    if ($config.deviceId -notmatch '^[0-9a-f]{32}$') { throw 'Invalid device identifier.' }
    $wlanOutput = & netsh.exe wlan show interfaces
    if ($LASTEXITCODE -ne 0) { return }
    $wlanText = $wlanOutput -join ([char]10)
    $ssidMatch = [regex]::Match($wlanText, '(?m)^\s*SSID\s*:\s*(.*?)\s*$')
    $ifMatch = [regex]::Match($wlanText, '(?m)^\s*Name\s*:\s*(.*?)\s*$')
    $stateMatch = [regex]::Match($wlanText, '(?m)^\s*State\s*:\s*(.*?)\s*$')
    if (-not $ssidMatch.Success -or
        $ssidMatch.Groups[1].Value.Trim() -cne 'POWIIS_Student' -or
        -not $stateMatch.Success -or
        $stateMatch.Groups[1].Value.Trim() -ne 'connected' -or
        -not $ifMatch.Success) { return }

    # Avoid reporting a private VPN/tunnel address as "campus IP".
    $wifiAlias = $ifMatch.Groups[1].Value.Trim()
    $defaultRoutes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop)
    $ranked = @($defaultRoutes | ForEach-Object {
        $iface = Get-NetIPInterface -InterfaceAlias $_.InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop
        [pscustomobject]@{
            Alias = $_.InterfaceAlias
            Metric = $_.RouteMetric + $iface.InterfaceMetric
        }
    } | Sort-Object Metric)
    if ($ranked.Count -eq 0 -or $ranked[0].Alias -cne $wifiAlias) { return }
    $tunnels = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and (
          $_.InterfaceDescription -match '(?i)wireguard|wintun|openvpn|tap-windows|tailscale|zerotier|cloudflare warp' -or
          $_.Name -match '(?i)vpn|tailscale|wireguard|warp'
        )
    })
    if ($tunnels.Count -gt 0) { return }

    $protected = ConvertTo-SecureString -String $config.keyProtected
    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($protected)
        $secretHex = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
    if ($secretHex -notmatch '^[0-9a-f]{64}$') { throw 'Invalid secured beacon key.' }
    $secret = New-Object byte[] 32
    for ($i=0; $i -lt 32; $i++) {
        $secret[$i] = [Convert]::ToByte($secretHex.Substring($i*2,2),16)
    }
    $secretHex = $null
    $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $nonce = [Guid]::NewGuid().ToString('N')
    $message = [string]::Join([char]10, @('v1',[string]$ts,$nonce,[string]$config.deviceId,[string]$config.ssid))
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 (,$secret)
    try {
        $digest = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
        $signature = -join ($digest | ForEach-Object { $_.ToString('x2') })
    } finally {
        $hmac.Dispose()
        [Array]::Clear($secret,0,$secret.Length)
    }
    $body = @{ts=$ts;nonce=$nonce;deviceId=$config.deviceId;ssid=$config.ssid} | ConvertTo-Json -Compress
    $tmp = Join-Path $env:TEMP ("vynalth-school-beacon-"+[Guid]::NewGuid().ToString('N')+".json")
    try {
        [IO.File]::WriteAllText($tmp,$body,[Text.Encoding]::UTF8)
        $argsCurl = @('-4','--noproxy','*','-sS','--max-time','15','-X','POST','-H','Content-Type: application/json','-H',("x-school-beacon-signature: "+$signature),'--data-binary',("@"+$tmp),$endpoint)
        $reply = & curl.exe @argsCurl
        if ($LASTEXITCODE -ne 0) { throw "Network failure code $LASTEXITCODE" }
        $response = $reply | ConvertFrom-Json
        if ($response.status) {
            Write-Output ("Vynalth School Beacon: "+$response.status)
        } else {
            Write-Output ("Vynalth School Beacon: "+$response.error)
        }
    } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
} catch {
    Write-Warning ("Vynalth School Beacon skipped: "+$_.Exception.Message)
}
