param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$OutDir = '',
    [switch]$MetadataOnly,
    [string]$Password = '',
    [string]$UsersDat = '',
    [switch]$KeepPayload,
    [string]$OpenSsl = 'C:\Program Files\Git\usr\bin\openssl.exe',
    [string]$Tar = 'C:\Windows\System32\tar.exe'
)
# Unpack Regul user backup (*.dat):
#   64K metadata (gzip meta.tar + SHA1/SHA224 trailer)
#   + openssl enc -aes-256-cbc (tar.gz of /mnt/user)
#   + SHA1/SHA224 of the whole file
# Usage:
#   .\open-backup.ps1 -Path .\backup\PLC_xxx.dat -MetadataOnly
#   .\open-backup.ps1 -Path .\backup\PLC_xxx.dat
#   .\open-backup.ps1 -Path .\backup\PLC_xxx.dat -UsersDat .\backup\users.dat
$ErrorActionPreference = 'Continue'
$enc = [Text.Encoding]::GetEncoding(28591)

function Run-Exe {
    param([string]$File, [string]$Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return [pscustomobject]@{ Out = $out; Err = $err; Exit = $p.ExitCode }
}

if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
if (-not (Test-Path -LiteralPath $OpenSsl)) { throw "openssl not found: $OpenSsl" }
if (-not (Test-Path -LiteralPath $Tar)) { throw "tar not found: $Tar" }

$item = Get-Item -LiteralPath $Path
if (-not $OutDir) {
    if ($MetadataOnly) { $OutDir = Join-Path $env:TEMP ("regul-meta-" + $item.BaseName) }
    else { $OutDir = Join-Path $item.DirectoryName ("extract-" + $item.BaseName) }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$bytes = [IO.File]::ReadAllBytes($item.FullName)
$len = $bytes.Length
"file  : $($item.FullName)"
"size  : $len"

# --- trailer digest: SHA1 (20) or SHA224 (28) ---
$digestLen = 0
$digestName = ''
$bodyLen = $len - 20
if ($bodyLen -gt 65536) {
    $sha1 = [Security.Cryptography.SHA1]::Create()
    $h = $sha1.ComputeHash($bytes, 0, $bodyLen)
    $tail = New-Object byte[] 20
    [Array]::Copy($bytes, $bodyLen, $tail, 0, 20)
    if ([BitConverter]::ToString($h) -eq [BitConverter]::ToString($tail)) { $digestLen = 20; $digestName = 'sha1' }
}
if ($digestLen -eq 0) {
    $bodyLen = $len - 28
    if ($bodyLen -gt 65536) {
        $bodyPath = Join-Path $OutDir 'body.tmp'
        $fs = [IO.File]::Create($bodyPath); $fs.Write($bytes, 0, $bodyLen); $fs.Close()
        $r = Run-Exe $OpenSsl ("dgst -sha224 -r `"$bodyPath`"")
        Remove-Item $bodyPath -Force -ErrorAction SilentlyContinue
        $hx = (($r.Out -split '\s+')[0]).Trim().ToLower()
        $tailHex = -join ($bytes[$bodyLen..($len - 1)] | ForEach-Object { $_.ToString('x2') })
        if ($hx -eq $tailHex) { $digestLen = 28; $digestName = 'sha224' }
    }
}
if ($digestLen -eq 0) { throw 'Trailer digest does not match SHA1/SHA224' }
"digest: $digestName ($digestLen bytes)"

# --- metadata (first 64K) ---
$metaLen = 65536
$metaGz = Join-Path $OutDir 'meta.gz'
$metaTar = Join-Path $OutDir 'meta.tar'
$meta = New-Object byte[] $metaLen
[Array]::Copy($bytes, 0, $meta, 0, $metaLen)
[IO.File]::WriteAllBytes($metaGz, $meta)
$in = [IO.File]::OpenRead($metaGz)
$gz = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
$out = [IO.File]::Create($metaTar)
$gz.CopyTo($out); $out.Close(); $gz.Close(); $in.Close()
"meta  :"
foreach ($k in @('targetId','version','com_module','backuphostname','backupdate','backupparts','backupdirs','backup_base_files','backup_user_files','osname')) {
    $r = Run-Exe $Tar ("-xOf `"$metaTar`" $k")
    $v = ($r.Out -join ' ').Trim()
    if ($v) { "  $k = $v" }
}

if ($MetadataOnly) { "metadata only: $OutDir"; exit 0 }

# --- payload ---
$payloadLen = $len - $metaLen - $digestLen
$payload = New-Object byte[] $payloadLen
[Array]::Copy($bytes, $metaLen, $payload, 0, $payloadLen)
$payloadPath = Join-Path $OutDir 'payload.bin'
[IO.File]::WriteAllBytes($payloadPath, $payload)
"payload: $payloadLen bytes"

$passwords = @()
if ($Password) { $passwords = @($Password) } else { $passwords = @('pscrypt','pskpdacrypt') }
$publicTar = Join-Path $OutDir 'public.tar.gz'
$usedPassword = ''
foreach ($pw in $passwords) {
    if (Test-Path -LiteralPath $publicTar) { Remove-Item $publicTar -Force }
    $r = Run-Exe $OpenSsl ("enc -d -aes-256-cbc -md md5 -pass pass:$pw -in `"$payloadPath`" -out `"$publicTar`"")
    if (-not (Test-Path -LiteralPath $publicTar)) { continue }
    $fb = New-Object byte[] 2
    $fs = [IO.File]::OpenRead($publicTar); $fs.Read($fb, 0, 2) | Out-Null; $fs.Close()
    if ($fb[0] -eq 0x1f -and $fb[1] -eq 0x8b) { $usedPassword = $pw; break }
}
if (-not $usedPassword) { throw 'Could not decrypt payload with pscrypt/pskpdacrypt' }
"cipher: aes-256-cbc/md5, password=$usedPassword"
"public: $publicTar ($((Get-Item $publicTar).Length) bytes)"

# --- extract public tar ---
$pubDir = Join-Path $OutDir 'public'
New-Item -ItemType Directory -Force -Path $pubDir | Out-Null
$r = Run-Exe $Tar ("-xzf `"$publicTar`" -C `"$pubDir`"")
if ($r.Exit -ne 0) { "tar warnings: $($r.Err.Trim())" }
$files = @(Get-ChildItem $pubDir -Recurse -File -Force -ErrorAction SilentlyContinue)
"public: $($files.Count) files -> $pubDir"
$pat = 'updateFW|fw\.key|make_regul|\.fwe$|\.ifs$|UserMgmtDB|UserDatabase|GroupDatabase|\.key$|\.pem$|\.crt$|\.der$|shadow|passwd'
$hits = $files | Where-Object { $_.Name -match $pat -or $_.FullName -match '\.codesys' }
if ($hits) {
    "interesting files:"
    $hits | Select-Object -First 80 | ForEach-Object { "  $($_.FullName) ($($_.Length))" }
} else {
    "no firmware/key/users files matched"
}

# --- optional users.dat ---
if ($UsersDat) {
    if (-not (Test-Path -LiteralPath $UsersDat)) { throw "UsersDat not found: $UsersDat" }
    $usersTar = Join-Path $OutDir 'users.tar.gz'
    $ok = ''
    foreach ($pw in $passwords) {
        if (Test-Path -LiteralPath $usersTar) { Remove-Item $usersTar -Force }
        $r = Run-Exe $OpenSsl ("enc -d -aes-256-cbc -md md5 -pass pass:$pw -in `"$UsersDat`" -out `"$usersTar`"")
        if (-not (Test-Path -LiteralPath $usersTar)) { continue }
        $fb = New-Object byte[] 2
        $fs = [IO.File]::OpenRead($usersTar); $fs.Read($fb, 0, 2) | Out-Null; $fs.Close()
        if ($fb[0] -eq 0x1f -and $fb[1] -eq 0x8b) { $ok = $pw; break }
    }
    if (-not $ok) { "users.dat: could not decrypt" }
    else {
        "users.dat: password=$ok"
        $usersDir = Join-Path $OutDir 'users'
        New-Item -ItemType Directory -Force -Path $usersDir | Out-Null
        $r = Run-Exe $Tar ("-xzf `"$usersTar`" -C `"$usersDir`"")
        if ($r.Exit -ne 0) { "users tar warnings: $($r.Err.Trim())" }
        Get-ChildItem $usersDir -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First 80 | ForEach-Object { "  $($_.FullName) ($($_.Length))" }
    }
}

if (-not $KeepPayload) { Remove-Item $payloadPath -Force -ErrorAction SilentlyContinue }
"done: $OutDir"
