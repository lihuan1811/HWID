<#
setup_redirect.ps1 —— 把 111.229.48.214 劫持到本机（这样 fake_server 才能收到它的连接）
用法（管理员 PowerShell）：
    .\setup_redirect.ps1            # 建立劫持
    .\setup_redirect.ps1 -Remove    # 撤销
#>
param([switch]$Remove, [string]$ServerIp = '111.229.48.214')

$ifName = (Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Loopback*' -or $_.Name -like '*Loopback*' } | Select-Object -First 1).Name
if (-not $ifName) { $ifName = 'Loopback Pseudo-Interface 1' }

if ($Remove) {
    netsh interface ipv4 delete address name="$ifName" address=$ServerIp 2>&1 | Out-Null
    Write-Host "[+] 已撤销劫持：$ServerIp"
    Write-Host "[i] 如需清理 hosts，请手动删除相关行"
    exit 0
}

Write-Host "[i] 网卡: $ifName"
netsh interface ipv4 add address name="$ifName" address=$ServerIp mask=255.255.255.255 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "[+] 已把 $ServerIp 绑到本机回环（程序连它会连到你）" }
else { Write-Host "[!] 绑定失败，试试用管理员权限重新运行" }

# 顺手把可能用到的域名也指过来（如果它除了 IP 还解析域名）
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
foreach ($d in @('hwidmaster.com','hwid-master.com')) {
    if (-not (Select-String -Path $hosts -Pattern "\s$d$" -Quiet -ErrorAction SilentlyContinue)) {
        Add-Content -Path $hosts -Value "127.0.0.1 $d"
        Write-Host "[+] hosts += $d"
    }
}
Write-Host ""
Write-Host "下一步：python fake_server.py --ports 80,8080,8888,9000,9999,5211,27112,3389,10086 --mode log"
