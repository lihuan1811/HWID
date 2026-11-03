<#
win_probe.ps1 —— 在无 Windows 桌面可用时，用 Windows runner 做"入口点(EP)探测 + 内存转储"

做什么：
  1. 读样本 PE 头，拿到当前 EP 与段表
  2. 先用**原始 EP** 跑一次：记录是否起窗口 / 存活多久 / 退出码 / 崩溃模块与偏移
  3. 依次把 EP 改成壳 stub 区的候选 RVA 再跑：只要出现窗口或进程存活 → procdump -ma 抓全内存
  4. 全程记录：新建的 %TEMP%%APPDATA%%LOCALAPPDATA% 文件、HKCU\Software 新键（授权常见落点）

用法：
  pwsh ./scripts/win_probe.ps1 -Exe samples\HWIDMaster-0902.exe -Procdump tools\procdump64.exe -OutDir probe
  可选：-EpList 0x5191000,0x5192000   -WaitSeconds 20   -NoRegistry
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [string]$Procdump = '',
  [string]$OutDir = 'probe',
  [string[]]$EpList = @('0x5191000', '0x5192000', '0x5193000', '0x51A0000'),
  [int]$WaitSeconds = 20,
  [switch]$NoRegistry
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

function Log($msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg
  Write-Host $line
  Add-Content -Path (Join-Path $OutDir 'run.log') -Value $line -Encoding utf8
}

# ---------------------------------------------------------------- PE 工具
function Get-PEInfo([string]$path) {
  $b = [System.IO.File]::ReadAllBytes($path)
  $pe = [BitConverter]::ToInt32($b, 0x3C)
  if ([System.Text.Encoding]::ASCII.GetString($b, $pe, 4) -ne 'PE' + [char]0 + [char]0) {
    throw "不是有效 PE: $path"
  }
  $nsec = [BitConverter]::ToUInt16($b, $pe + 6)
  $soh = [BitConverter]::ToUInt16($b, $pe + 20)
  $opt = $pe + 24
  $magic = [BitConverter]::ToUInt16($b, $opt)
  $is64 = ($magic -eq 0x20b)
  $ep = [BitConverter]::ToUInt32($b, $opt + 16)
  $ib = if ($is64) { [BitConverter]::ToUInt64($b, $opt + 24) } else { [BitConverter]::ToUInt32($b, $opt + 28) }
  $secoff = $opt + $soh
  $secs = @()
  for ($i = 0; $i -lt $nsec; $i++) {
    $o = $secoff + $i * 40
    $name = [System.Text.Encoding]::ASCII.GetString($b, $o, 8).TrimEnd([char]0)
    $vs = [BitConverter]::ToUInt32($b, $o + 8)
    $va = [BitConverter]::ToUInt32($b, $o + 12)
    $rs = [BitConverter]::ToUInt32($b, $o + 16)
    $ra = [BitConverter]::ToUInt32($b, $o + 20)
    $ch = [BitConverter]::ToUInt32($b, $o + 36)
    $secs += [pscustomobject]@{ Name = $name; VA = $va; VS = $vs; RA = $ra; RS = $rs; Ch = $ch }
  }
  return [pscustomobject]@{ Bytes = $b; PeOff = $pe; Opt = $opt; EP = $ep; ImageBase = $ib; Sections = $secs; Is64 = $is64 }
}

function Set-EP([string]$src, [string]$dst, [uint32]$rva) {
  Copy-Item $src $dst -Force
  $b = [System.IO.File]::ReadAllBytes($dst)
  $pe = [BitConverter]::ToInt32($b, 0x3C)
  $opt = $pe + 24
  [BitConverter]::GetBytes([uint32]$rva).CopyTo($b, $opt + 16)
  [BitConverter]::GetBytes([uint32]0).CopyTo($b, $opt + 64)   # 清校验和
  [System.IO.File]::WriteAllBytes($dst, $b)
}

function Get-Snapshot {
  $snap = @{}
  foreach ($d in @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA)) {
    if ($d -and (Test-Path $d)) {
      $snap[$d] = @(Get-ChildItem $d -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    }
  }
  return $snap
}

function Diff-Snapshot($before) {
  $out = @()
  foreach ($d in $before.Keys) {
    $now = @(Get-ChildItem $d -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    $new = $now | Where-Object { $before[$d] -notcontains $_ }
    if ($new) { $out += [pscustomobject]@{ Dir = $d; New = ($new -join ', ') } }
  }
  return $out
}

function Get-RunKeys {
  $keys = @()
  foreach ($root in @('HKCU:\Software', 'HKLM:\SOFTWARE')) {
    try {
      $keys += Get-ChildItem $root -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    } catch { }
  }
  return $keys
}

function Get-CrashInfo([string]$procName, [datetime]$since) {
  $res = @()
  try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $since } -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match [regex]::Escape($procName) } |
      Select-Object -First 6 |
      ForEach-Object {
        $res += [pscustomobject]@{
          Time     = $_.TimeCreated.ToString('HH:mm:ss')
          Provider = $_.ProviderName
          Id       = $_.Id
          Level    = $_.LevelDisplayName
          Message  = ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(700, $_.Message.Length))
        }
      }
  } catch { }
  return $res
}

# ---------------------------------------------------------------- 主流程
New-Item -ItemType Directory -Force -Path $OutDir, (Join-Path $OutDir 'dumps'), (Join-Path $OutDir 'patched') | Out-Null
Log "输出目录: $((Resolve-Path $OutDir).Path)"

if (-not (Test-Path $Exe)) { throw "找不到样本: $Exe" }
$info = Get-PEInfo $Exe
Log ("样本: {0}  {1:N0} 字节" -f $Exe, (Get-Item $Exe).Length)
Log ("PE: {0}位 ImageBase={1:X} 当前EP(RVA)={2:X}  段数={3}" -f `
    ($(if ($info.Is64) { 64 } else { 32 })), $info.ImageBase, $info.EP, $info.Sections.Count)
$info.Sections | ForEach-Object {
  Log ("  段 {0,-10} VA={1:X8} VS={2:X8} RAW={3:X8} RS={4:X8} {5}" -f `
      $_.Name, $_.VA, $_.VS, $_.RA, $_.RS, $(if ($_.Ch -band 0x20000000) { 'X' } else { '' }))
}

$report = @()
$baseHku = if ($NoRegistry) { @() } else { Get-RunKeys }

# ---- 跑一次（$label, $exePath, $epRva）
function Invoke-Probe([string]$label, [string]$exePath, [string]$epRva) {
  Log "===== 探测 [$label] EP=$epRva ====="
  $procName = [System.IO.Path]::GetFileNameWithoutExtension($exePath)
  $before = Get-Snapshot
  $t0 = Get-Date
  $p = $null
  try {
    $p = Start-Process -FilePath $exePath -PassThru -WorkingDirectory (Split-Path $exePath) -ErrorAction Stop
  } catch {
    Log "  启动失败: $($_.Exception.Message)"
    return [pscustomobject]@{ Label = $label; EP = $epRva; Started = $false; Error = $_.Exception.Message }
  }
  Log ("  已启动 PID={0}" -f $p.Id)

  $titled = ''
  $alive = 0
  for ($i = 0; $i -lt ($WaitSeconds * 4); $i++) {
    Start-Sleep -Milliseconds 250
    $p.Refresh()
    if ($p.HasExited) { break }
    $alive = $i * 0.25
    try {
      if (-not $titled -and $p.MainWindowTitle) { $titled = $p.MainWindowTitle }
    } catch { }
    if ($titled) { $alive = [Math]::Round($i * 0.25, 1); break }   # 窗口出来了就停，别等
  }
  $p.Refresh()

  $row = [pscustomobject]@{
    Label        = $label
    EP           = $epRva
    Started      = $true
    Exited       = $p.HasExited
    ExitCode     = $(if ($p.HasExited) { $p.ExitCode } else { $null })
    WindowTitle  = $titled
    AliveSeconds = $alive
    Dump         = ''
    Crash        = ''
    NewFiles     = ''
    NewRegKeys   = ''
  }

  if (-not $p.HasExited) {
    Log ("  进程存活 {0}s，窗口标题='{1}' → 抓全内存" -f $alive, $titled)
    if ($Procdump -and (Test-Path $Procdump)) {
      $dump = Join-Path $OutDir ("dumps\{0}.dmp" -f ($label -replace '[^\w\-]', '_'))
      & $Procdump -accepteula -ma -t $p.Id $dump 2>&1 | ForEach-Object { Log "    procdump: $_" }
      if (Test-Path $dump) {
        $row.Dump = $dump
        Log ("    dump: {0} ({1:N1} MB)" -f $dump, ((Get-Item $dump).Length / 1MB))
      }
    } else {
      Log "    未提供 procdump，跳过 dump"
    }
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  } else {
    Log ("  已退出，退出码={0}" -f $row.ExitCode)
    $crash = Get-CrashInfo $procName $t0
    if ($crash) {
      $row.Crash = ($crash | ForEach-Object { "[$($_.Provider)/$($_.Id)] $($_.Message)" }) -join ' || '
      $crash | ForEach-Object { Log ("    事件: [{0}/{1}] {2}" -f $_.Provider, $_.Id, $_.Message) }
    } else {
      Log "    事件日志里没有该进程的崩溃记录"
    }
  }

  $diff = Diff-Snapshot $before
  if ($diff) {
    $row.NewFiles = ($diff | ForEach-Object { "$($_.Dir) -> $($_.New)" }) -join ' || '
    $diff | ForEach-Object { Log ("    新文件: {0} -> {1}" -f $_.Dir, $_.New) }
  }
  if (-not $NoRegistry) {
    $nowKeys = Get-RunKeys
    $newKeys = $nowKeys | Where-Object { $baseHku -notcontains $_ }
    if ($newKeys) {
      $row.NewRegKeys = ($newKeys -join ', ')
      Log ("    新注册表键: {0}" -f ($newKeys -join ', '))
    }
  }
  return $row
}

# 1) 原始 EP
$report += Invoke-Probe 'origin' (Resolve-Path $Exe).Path ('0x{0:X}' -f $info.EP)

# 2) EP 候选
foreach ($ep in $EpList) {
  $rva = [uint32]$ep
  $dst = Join-Path $OutDir ("patched\{0}\{1}" -f $ep, (Split-Path $Exe -Leaf))
  New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
  Set-EP (Resolve-Path $Exe).Path $dst $rva
  $report += Invoke-Probe "ep_$ep" $dst $ep
}

# ---------------------------------------------------------------- 报告
$report | Format-List | Out-String -Width 400 | Tee-Object -FilePath (Join-Path $OutDir 'report.txt')
$report | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir 'report.json') -Encoding utf8

$ok = $report | Where-Object { $_.WindowTitle -or $_.Dump }
if ($ok) {
  Log "===== 结论：有进程成功跑起来了 ====="
  $ok | ForEach-Object { Log ("  {0}: 窗口='{1}' dump='{2}'" -f $_.Label, $_.WindowTitle, $_.Dump) }
} else {
  Log "===== 结论：所有 EP 候选都没跑起来（见 report.txt 里的崩溃模块/偏移） ====="
  Log "下一步：把 report.txt 里的 'faulting module / exception offset' 拿回来，可定位正确入口；"
  Log "或改走路线：要卖家启动器 / 拿到能起界面的版本。"
}
