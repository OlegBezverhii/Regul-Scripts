param(
    [Parameter(Mandatory=$true)][string]$Path,
    [switch]$VerifyOnly
)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
public static class UserDbCrc {
    static uint[] t;
    static UserDbCrc() {
        t = new uint[256];
        for (uint i = 0; i < 256; i++) {
            uint c = i;
            for (int k = 0; k < 8; k++) c = ((c & 1) != 0) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
    }
    public static uint Compute(byte[] b) {
        uint c = 0xFFFFFFFFu;
        foreach (byte x in b) c = t[(c ^ x) & 0xFF] ^ (c >> 8);
        return c ^ 0xFFFFFFFFu;
    }
}
'@

$bytes = [IO.File]::ReadAllBytes($Path)
$text = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
$lines = $text -split "`r`n"
$idx = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^Checksum,0x([0-9a-fA-F]+)') { $idx = $i; break }
}
if ($idx -lt 0) { throw "Checksum line not found in $Path" }

$stored = [Convert]::ToUInt32(($lines[$idx] -replace '^Checksum,0x', ''), 16)
$dataLines = @()
if ($idx -gt 0) { $dataLines = $lines[0..($idx - 1)] }
$payload = [Text.Encoding]::GetEncoding(28591).GetBytes((-join $dataLines))
$crc = [UserDbCrc]::Compute($payload)
$match = ($crc -eq $stored)

"file      : $Path"
"stored    : 0x{0:x8}" -f $stored
"computed  : 0x{0:x8}" -f $crc
"match     : $match"

if ($VerifyOnly) {
    if (-not $match) { exit 1 }
    exit 0
}

if (-not $match) {
    $newLine = 'Checksum,0x{0:x8}' -f $crc
    $newText = [regex]::Replace($text, '(?m)^Checksum,0x[0-9a-fA-F]+', $newLine)
    [IO.File]::WriteAllBytes($Path, [Text.Encoding]::GetEncoding(28591).GetBytes($newText))
    "updated   : $Path -> $newLine"
} else {
    "unchanged"
}
