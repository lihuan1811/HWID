<#
win_probe2.ps1 —— 第二轮探针：抓"崩溃时刻"的内存 + 异常地址 + 存活期内存快照

第一轮结论（run 41568290403）：
  origin(EP=0x2AF1DD3) 活了 8 秒才 0xC0000005；EP 改到 stub 区的 4 个候选全部"瞬间"崩。
  → 原始入口那条路确实在执行东西，崩溃点很有价值。

本脚本做四件事：
  1. 开 WER LocalDumps（全内存、指定目录）→ 任何崩溃都留 dump
  2. 用 procdump -e -ma -t 直接"拉起并等异常"→ 拿到崩溃瞬间的全内存 + 打印异常地址
  3. 存活期内每隔 N 秒 procdump -ma 抓快照（origin 能活 8 秒，够抓 1~2 次）
  4. 记录存活期的模块列表（看它到底有没有走到网络/注册表）、WER 事件、CrashDumps 目录

用法：
  pwsh ./scripts/win_probe2.ps1 -Exe samples\HWIDMaster-0902.exe -Procdump tools\procdump64.exe -OutDir probe2
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [string]$Procdump = '',
  [string]$OutDir = 'probe2',
  [string[]]$EpList = @('0x5191000', '0x51A0000'),
  [int]$LiveSnapshotSeconds = 3,
  [int]$MaxLiveSnapshots = 2
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dumps = Join-Path $OutDir 'dumps'
New-Item -ItemType Directory -Force -Path $OutDir, $dumps | Out-Null

function Log($m) {
  $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
  Write-Host $line
  Add-Content (Join-Path $OutDir 'run.log') $line -Encoding utf8
}

# ---------------------------------------------------------------- WER LocalDumps
Log '=== 启用 WER LocalDumps（全内存）==='
$werKey = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
try {
  New-Item -Path $werKey -Force | Out-Null
  New-Item -Path "$werKey\HWIDMaster-0902.exe" -Force | Out-Null
  Set-ItemProperty "$werKey\HWIDMaster-0902.exe" -Name DumpFolder -Value (Resolve-Path $dumps).Path -Type ExpandString
  Set-ItemProperty "$werKey\HWIDMaster-0902.exe" -Name DumpType -Value 2 -Type DWord
  Set-ItemProperty "$werKey\HWIDMaster-0902.exe" -Name DumpCount -Value 5 -Type DWord
  Log "  DumpFolder=$((Resolve-Path $dumps).Path) DumpType=2"
} catch { Log "  WER 配置失败: $($_.Exception.Message)" }

# ---------------------------------------------------------------- PE 工具
function Set-EP([string]$src, [string]$dst, [uint32]$rva) {
  Copy-Item $src $dst -Force
  $b = [System.IO.File]::ReadAllBytes($dst)
  $pe = [BitConverter]::ToInt32($b, 0x3C); $opt = $pe + 24
  [BitConverter]::GetBytes([uint32]$rva).CopyTo($b, $opt + 16)
  [BitConverter]::GetBytes([uint32]0).CopyTo($b, $opt + 64)
  [System.IO.File]::WriteAllBytes($dst, $b)
}

function Show-Dumps($tag) {
  $found = @()
  foreach ($d in @($dumps, "$env:LOCALAPPDATA\CrashDumps", $env:TEMP)) {
    if ($d -and (Test-Path $d)) {
      $found += Get-ChildItem $d -Filter *.dmp -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) }
    }
  }
  $found | ForEach-Object {
    Log ("  [{0}] dump: {1}  {2:N1} MB  {3:HH:mm:ss}" -f $tag, $_.FullName, ($_.Length / 1MB), $_.LastWriteTime)
  }
  return $found
}

function Parse-ProcdumpOutput($lines) {
  $ex = @()
  foreach ($l in $lines) {
    if ($l -match 'Exception|exception|Dump \d|Access violation|address') { $ex += ($l -replace '\s+', ' ').Trim() }
  }
  return $ex
}

# ---------------------------------------------------------------- 场景 A：procdump 拉起 + 等异常
function Probe-Exception([string]$label, [string]$exePath) {
  Log "===== [$label] procdump -e -ma -t 拉起并等异常 ====="
  if (-not ($Procdump -and (Test-Path $Procdump))) { Log '  没有 procdump，跳过'; return }
  $out = Join-Path $dumps ("{0}_exc.dmp" -f $label)
  $t0 = Get-Date
  $lines = & $Procdump -accepteula -e -ma -t "$exePath" "$out" 2>&1 | ForEach-Object { "$_" }
  $dur = [Math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
  Log ("  procdump 返回，耗时 {0}s" -f $dur)
  $parsed = Parse-ProcdumpOutput $lines
  foreach ($l in $parsed) { Log "    | $l" }
  $lines | Out-File (Join-Path $OutDir ("procdump_{0}.txt" -f $label)) -Encoding utf8
  if (Test-Path $out) { Log ("  异常 dump: {0} ({1:N1} MB)" -f $out, ((Get-Item $out).Length / 1MB)) }
}

# ---------------------------------------------------------------- 场景 B：存活期定时快照
function Probe-Live([string]$label, [string]$exePath) {
  Log "===== [$label] 存活期快照 ====="
  $p = Start-Process -FilePath $exePath -PassThru -WorkingDirectory (Split-Path $exePath) -ErrorAction SilentlyContinue
  if (-not $p) { Log '  启动失败'; return }
  Log ("  已启动 PID={0}" -f $p.Id)
  for ($i = 1; $i -le $MaxLiveSnapshots; $i++) {
    Start-Sleep -Seconds $LiveSnapshotSeconds
    $p.Refresh()
    if ($p.HasExited) { Log ("  第 {0} 次快照前已退出，退出码={1}" -f $i, $p.ExitCode); break }
    # 模块与窗口状态
    try {
      $mods = (Get-Process -Id $p.Id).Modules | Select-Object -ExpandProperty ModuleName
      $mods | Out-File (Join-Path $OutDir ("modules_{0}_{1}.txt" -f $label, $i)) -Encoding utf8
      Log ("  第 {0} 次快照：已加载 {1} 个模块（ws2_32={2} advapi32={3} user32={4}）" -f `
          $i, $mods.Count, [bool]($mods -match 'ws2_32'), [bool]($mods -match 'advapi32'), [bool]($mods -match 'user32'))
      Log ("    窗口标题='{0}'  句柄={1}" -f $p.MainWindowTitle, $p.MainWindowHandle)
    } catch { Log "  模块读取失败: $($_.Exception.Message)" }
    if ($Procdump -and (Test-Path $Procdump)) {
      $snap = Join-Path $dumps ("{0}_live{1}.dmp" -f $label, $i)
      & $Procdump -accepteula -ma $p.Id $snap 2>&1 | ForEach-Object { Log "    procdump: $_" }
      if (Test-Path $snap) { Log ("    快照 {0}: {1:N1} MB" -f $snap, ((Get-Item $snap).Length / 1MB)) }
    }
  }
  $p.Refresh()
  if (-not $p.HasExited) { Log '  仍在运行 → 等它自然结束（最多 30s）'; $p.WaitForExit(30000) | Out-Null; $p.Refresh() }
  if ($p.HasExited) { Log ("  结束，退出码={0}" -f $p.ExitCode) } else { Log '  超时仍在跑 → 杀掉'; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  Show-Dumps $label | Out-Null
}

# ---------------------------------------------------------------- 跑
$exe = (Resolve-Path $Exe).Path
Log "样本: $exe"

Probe-Exception 'origin' $exe
Probe-Live 'origin' $exe

foreach ($ep in $EpList) {
  $dst = Join-Path $OutDir ("patched\{0}\{1}" -f $ep, (Split-Path $Exe -Leaf))
  New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
  Set-EP $exe $dst ([uint32]$ep)
  Probe-Exception ("ep_$ep") $dst
}

# ---------------------------------------------------------------- WER 事件 + 收尾
Log '=== WER / Application 日志事件 ==='
try {
  Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddMinutes(-20) } -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 1000, 1001, 1026 } |
    Select-Object -First 15 | ForEach-Object {
      Log ("  [{0}/{1}] {2}" -f $_.ProviderName, $_.Id, (($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(600, $_.Message.Length))))
    }
} catch { Log "  读事件失败: $($_.Exception.Message)" }

Log '=== 所有 dump 汇总 ==='
$all = Show-Dumps 'all'
$all | Select-Object FullName, Length, LastWriteTime | ConvertTo-Json | Out-File (Join-Path $OutDir 'dumps.json') -Encoding utf8
Log ("共 {0} 个 dump" -f @($all).Count)
Log 'DONE'
