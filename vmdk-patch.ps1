<#
.SYNOPSIS
    Поиск и замена байтовых подстрок внутри образа диска (vmdk/qcow2/raw) БЕЗ монтирования ФС.

.DESCRIPTION
    Скрипт не разбирает файловую систему (QNX6/ext4/...). Он работает как «grep + dd»:
    находит в контейнере заданную ASCII-подстроку и заменяет её на другую.

    Ключевые ограничения и правила:
      1. Замена по длине ДОЛЖНА совпадать со строкой поиска (или быть короче при -PadWithSpaces).
         Иначе поедут смещения и структура ФС будет разрушена: мы не обновляем inode/размер файла.
      2. Скрипт не знает, какому файлу принадлежит найденный фрагмент. Он может попасть
         в «живую» копию файла, в свободный блок (остатки от sed -i) или в другую копию
         файла (например, в образ .ifs). Для «живых» данных результат проверяется
         повторным чтением/монтированием; мусорные копии менять безвредно.
      3. Работает только для контейнеров, где данные гостя лежат открытым текстом:
         VMware Workstation/Player (monolithicSparse, grains без сжатия) — да;
         OVA/streamOptimized VMDK (сжатые grains), qcow2 с zstd — обычно нет
         (ищите через монтирование исходного образа на Linux).
      4. Все правки делать ТОЛЬКО при выключенной ВМ и при отсутствии .lck-файлов.

    Алгоритм сознательно двухфазный:
      фаза 1 — читаем файл потоком и собираем СМЕЩЕНИЯ (только чтение);
      фаза 2 — открываем файл на запись и пишем по собранным смещениям.
    Если писать в файл во время последовательного чтения, позиция чтения «уезжает»
    (мы наступили на это: часть замен легла не туда). Поэтому чтение и запись разнесены.

.PARAMETER Path
    Путь к файлу образа (vmdk/qcow2/raw/img).

.PARAMETER Old
    ASCII-строка для поиска. Регистрозависима. Может содержать переводы строк (`r`n / `n)
    при передаче из PowerShell в двойных кавычках.

.PARAMETER New
    Строка замены той же длины. Если не задана — скрипт только ищет (аналог -VerifyOnly).

.PARAMETER PadWithSpaces
    Разрешить замену более короткой строкой с добивкой пробелами до длины Old.

.PARAMETER VerifyOnly
    Только поиск и печать контекста, без записи.

.PARAMETER DryRun
    Показать, что будет заменено, но не писать.

.PARAMETER Context
    Сколько байт контекста печатать вокруг найденного фрагмента (по умолчанию 120).

.EXAMPLE
    # 1) Включить SSH в inetd.conf: 34-символьный маркер -> "ssh" + 31 пробел
    $m = '#-ssh-disabled from runtime.cfg--#'
    $r = 'ssh' + (' ' * 31)
    .\vmdk-patch.ps1 -Path 'C:\...\disk1.vmdk' -Old $m -New $r

.EXAMPLE
    # 2) Снять 24-часовой таймер: && -> || (2 байта)
    .\vmdk-patch.ps1 -Path 'C:\...\disk1.vmdk' -Old 'sleep 86400 &&' -New 'sleep 86400 ||'

.EXAMPLE
    # 3) Прописать DES-хэш root в /etc/shadow (блок целиком, длина та же)
    $old = "root:*:1459159315:0:0`nplclogs:H38VMaWovpUYU:1467293921:0:0`nplcuser:7DDi5jPU0JkRA:1467293978:0:0"
    $new = "root:abWKPtL.M8W9Q::0`nplclogs:H38VMaWovpUYU:1467293921:0:0`nplcuser:7DDi5jPU0JkRA:1467293978:0:0"
    .\vmdk-patch.ps1 -Path 'C:\...\disk1.vmdk' -Old $old -New $new

.EXAMPLE
    # 4) Только поиск с контекстом (ничего не менять)
    .\vmdk-patch.ps1 -Path 'C:\...\disk1.vmdk' -Old 'root:*:' -VerifyOnly
#>
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Old,
    [string]$New = $null,
    [switch]$PadWithSpaces,
    [switch]$VerifyOnly,
    [switch]$DryRun,
    [int]$Context = 120
)

$ErrorActionPreference = 'Stop'
$enc = [Text.Encoding]::GetEncoding(28591)   # Latin-1: байт <-> символ 1:1

if (-not (Test-Path -LiteralPath $Path)) { throw "Файл не найден: $Path" }
if ($Old.Length -eq 0) { throw 'Пустая строка поиска' }

$doWrite = -not $VerifyOnly -and -not [string]::IsNullOrEmpty($New)

if ($doWrite) {
    if ($New.Length -lt $Old.Length -and $PadWithSpaces) {
        $New = $New + (' ' * ($Old.Length - $New.Length))
    }
    if ($New.Length -ne $Old.Length) {
        throw "Длина замены ($($New.Length)) не равна длине шаблона ($($Old.Length)). " +
              'Для сохранения структуры ФС длины должны совпадать (или используйте -PadWithSpaces).'
    }
}

# ---------- фаза 1: только чтение, собираем смещения ----------
$rfs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
try {
    $bufSize = 8MB
    $buf = New-Object byte[] $bufSize
    $overlap = [Math]::Max(0, $Old.Length - 1)
    $over = ''
    $pos = 0
    $offsets = New-Object System.Collections.ArrayList
    $samples = New-Object System.Collections.ArrayList

    while ($true) {
        $n = $rfs.Read($buf, 0, $bufSize)
        if ($n -le 0) { break }
        $s = $over + $enc.GetString($buf, 0, $n)
        $base = $pos - $over.Length
        $i = 0
        while ($true) {
            $i = $s.IndexOf($Old, $i, [StringComparison]::Ordinal)
            if ($i -lt 0) { break }
            $abs = $base + $i
            [void]$offsets.Add($abs)
            if ($samples.Count -lt 10) {
                $st = [Math]::Max(0, $i - $Context)
                $len = [Math]::Min($Context * 2, $s.Length - $st)
                $frag = $s.Substring($st, $len) -replace '[^\x20-\x7E\r\n]', '.'
                [void]$samples.Add("offset=$abs`n$frag")
            }
            $i += $Old.Length
        }
        $pos += $n
        if ($s.Length -gt $overlap) { $over = $s.Substring($s.Length - $overlap) } else { $over = $s }
    }
}
finally {
    $rfs.Close()
}

"matches=$($offsets.Count)"
foreach ($smp in $samples) { "--- $smp" }

# ---------- фаза 2: запись по собранным смещениям ----------
if ($offsets.Count -gt 0 -and $doWrite -and -not $DryRun) {
    $bytes = $enc.GetBytes($New)
    $wfs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        foreach ($o in $offsets) {
            $wfs.Seek($o, [IO.SeekOrigin]::Begin) | Out-Null
            $wfs.Write($bytes, 0, $bytes.Length)
            "patched @ $o"
        }
        $wfs.Flush()
    }
    finally {
        $wfs.Close()
    }
}
elseif ($DryRun) {
    'DryRun: запись не выполнялась'
}
