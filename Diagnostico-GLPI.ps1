#requires -Version 5.1
<#
.SYNOPSIS
    Fase 2a - Diagnostico remoto READ-ONLY de uma estacao Windows, postando o
    relatorio como acompanhamento no chamado do GLPI.

.DESCRIPTION
    Roda NO DOMAIN CONTROLLER (sessao Domain Admin). Fluxo:
      1. Le config do GLPI (URL + tokens) de um arquivo JSON ou de variaveis de ambiente.
      2. initSession na API GLPI (conta de servico ipe.ia) + entidade raiz recursiva.
      3. Resolve o hostname: usa -Hostname se dado; senao tenta pelo solicitante do
         chamado via inventario (funciona quando o inventario estiver populado).
      4. Coleta READ-ONLY via WinRM/Invoke-Command (um unico ScriptBlock).
      5. Monta relatorio determinístico (Resumo + Achados + Rede + Dados).
      6. POST do acompanhamento (ITILFollowup) no chamado. killSession.

    GUARD-RAIL: o ScriptBlock remoto contem SOMENTE comandos de leitura
    (Get-*, Test-*, Resolve-*, Measure-*, Get-CimInstance, Get-WinEvent, netsh show).
    Nenhum verbo mutante. O carater read-only e garantido pelo conteudo deste script.

.PARAMETER TicketId
    Numero do chamado no GLPI (obrigatorio).

.PARAMETER Hostname
    Nome da estacao alvo. Opcional: se omitido, resolve pelo solicitante do chamado.

.PARAMETER ConfigPath
    Caminho do JSON de config { "Url","AppToken","UserToken" }. Default:
    <pasta-do-script>\glpi-config.json. Alternativa: variaveis de ambiente
    GLPI_PUBLIC_URL / GLPI_APP_TOKEN / GLPI_USER_TOKEN.

.PARAMETER Preview
    Nao posta no chamado: imprime o HTML do relatorio no console (para teste).

.PARAMETER SkipCertCheck
    Ignora validacao do certificado TLS (usar so fora do dominio; no DC a CA e confiavel).

.EXAMPLE
    .\Diagnostico-GLPI.ps1 -TicketId 7490 -Hostname PC01
.EXAMPLE
    .\Diagnostico-GLPI.ps1 -TicketId 7490 -Preview
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][int]$TicketId,
    [string]$Hostname,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'glpi-config.json'),
    [string]$InternalIp,
    [string]$InternalDnsName,
    [string]$ExternalDnsName = 'www.microsoft.com',
    [string]$InternetIp = '1.1.1.1',
    [string]$MailHost = 'outlook.office365.com',
    [int]$MailPort = 443,
    [switch]$Preview,
    [switch]$Auto,          # modo poller: em "sem host/offline" posta nota e sai 0 (nao lanca)
    [switch]$SkipCertCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'src\GlpiDiagnostico.psm1') -Force

# ------------------------------------------------------------------ Config ---
function Get-GlpiConfig {
    param([string]$Path)
    $j = $null
    if (Test-Path $Path) { $j = Get-Content $Path -Raw | ConvertFrom-Json }
    $url = $env:GLPI_PUBLIC_URL; if (-not $url) { $url = Get-Prop $j 'Url' $null }
    $app = $env:GLPI_APP_TOKEN;  if (-not $app) { $app = Get-Prop $j 'AppToken' $null }
    $usr = $env:GLPI_USER_TOKEN; if (-not $usr) { $usr = Get-Prop $j 'UserToken' $null }
    if (-not $url -or -not $app -or -not $usr) {
        throw "Config incompleta. Defina GLPI_PUBLIC_URL/GLPI_APP_TOKEN/GLPI_USER_TOKEN ou crie $Path (Url/AppToken/UserToken)."
    }
    return [pscustomobject]@{
        Base            = "$($url.TrimEnd('/'))/apirest.php"
        App             = $app
        User            = $usr
        Public          = $url.TrimEnd('/')
        InternalIp      = (Get-Prop $j 'InternalIp' $null)       # opcional: alvo de ping interno (ex.: DC)
        InternalDnsName = (Get-Prop $j 'InternalDnsName' $null)  # opcional: nome interno p/ testar DNS
    }
}

# ------------------------------------------------------------- API GLPI ------
$script:Cfg = $null
$script:Session = $null

function Invoke-Glpi {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Get', 'Post')][string]$Method = 'Get',
        $Body
    )
    $h = @{ 'App-Token' = $script:Cfg.App }
    if ($script:Session) { $h['Session-Token'] = $script:Session }
    $uri = "$($script:Cfg.Base)/$Path"
    if ($Method -eq 'Post') {
        $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 8 }
        # Enviar como bytes UTF-8: no PS5.1 -Body string pode ser codificado sem UTF-8 e
        # corromper acentos/emoji (viram '?'). Bytes + charset garante a codificacao.
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $h['Content-Type'] = 'application/json; charset=utf-8'
        return Invoke-RestMethod -Uri $uri -Headers $h -Method Post -Body $bytes -TimeoutSec 30
    }
    $h['Content-Type'] = 'application/json'
    return Invoke-RestMethod -Uri $uri -Headers $h -Method Get -TimeoutSec 30
}

function Connect-Glpi {
    $h = @{ 'Content-Type' = 'application/json'; 'App-Token' = $script:Cfg.App; 'Authorization' = "user_token $($script:Cfg.User)" }
    $r = Invoke-RestMethod -Uri "$($script:Cfg.Base)/initSession" -Headers $h -Method Get -TimeoutSec 30
    $script:Session = $r.session_token
    # Entidade raiz recursiva: para enxergar computadores de toda a arvore quando o inventario existir.
    try { Invoke-Glpi -Path 'changeActiveEntities' -Method Post -Body @{ input = @{ entities_id = 0; is_recursive = $true } } | Out-Null } catch { }
}

function Disconnect-Glpi {
    if ($script:Session) { try { Invoke-Glpi -Path 'killSession' | Out-Null } catch { }; $script:Session = $null }
}

function Get-TicketRequesterId {
    param([int]$Id)
    $rows = @(Invoke-Glpi -Path "Ticket/$Id/Ticket_User")
    $req = $rows | Where-Object { (Get-Prop $_ 'type' 0) -eq 1 -and [int](Get-Prop $_ 'users_id' 0) -gt 0 } | Select-Object -First 1
    if ($req) { return [int]$req.users_id }
    return 0
}

function Get-UserLogin {
    param([int]$Id)
    try { return (Invoke-Glpi -Path "User/$Id").name } catch { return $null }
}

function Resolve-HostnameFromTicket {
    param([int]$Id)
    $uid = Get-TicketRequesterId -Id $Id
    if ($uid -le 0) { return $null }
    # (1) por Usuario associado ao ativo  -> field 70 (Computer.User.name), equals users_id
    $byUser = Invoke-Glpi -Path "search/Computer?criteria[0][field]=70&criteria[0][searchtype]=equals&criteria[0][value]=$uid&forcedisplay[0]=1&range=0-9"
    $names = @()
    foreach ($row in @(Get-Prop $byUser 'data' @())) { $n = Get-Prop $row '1' $null; if ($n) { $names += $n } }
    # (2) fallback por 'contact' (usuario alternativo/logado reportado pelo agente) -> field 7 contains login
    if ($names.Count -eq 0) {
        $login = Get-UserLogin -Id $uid
        if ($login) {
            $byContact = Invoke-Glpi -Path "search/Computer?criteria[0][field]=7&criteria[0][searchtype]=contains&criteria[0][value]=$login&forcedisplay[0]=1&range=0-9"
            foreach ($row in @(Get-Prop $byContact 'data' @())) { $n = Get-Prop $row '1' $null; if ($n) { $names += $n } }
        }
    }
    $names = @($names | Select-Object -Unique)
    if ($names.Count -eq 1) { return $names[0] }
    if ($names.Count -gt 1) { throw "Solicitante tem $($names.Count) computadores no inventario ($($names -join ', ')). Rode com -Hostname para escolher." }
    return $null
}

function Add-TicketDiagnostico {
    param([int]$Id, [string]$Html)
    $body = New-GlpiFollowupBody -TicketId $Id -Html $Html -IsPrivate 0
    return Invoke-Glpi -Path 'ITILFollowup' -Method Post -Body $body
}

# --------------------------------------------------- Coleta READ-ONLY (WinRM) ---
# ScriptBlock executado NA ESTACAO (PS 5.1). SOMENTE leitura. Devolve hashtable.
$CollectScript = {
    param($InternalIp, $InternalDnsName, $ExternalDnsName, $InternetIp, $MailHost, $MailPort)

    $errs = New-Object System.Collections.Generic.List[string]
    function safe($name, $sb) { try { & $sb } catch { $errs.Add("$name= $($_.Exception.Message)"); $null } }

    # Estatistica de ping portatil (PS5.1 ResponseTime / PS7 Latency|Reply)
    function Ping-Stats($target, $count = 12) {
        if (-not $target) { return $null }
        $r = Test-Connection -ComputerName $target -Count $count -ErrorAction SilentlyContinue
        $lat = foreach ($x in @($r)) {
            if ($x.PSObject.Properties.Name -contains 'ResponseTime') { $x.ResponseTime }
            elseif ($x.PSObject.Properties.Name -contains 'Latency') {
                if (($x.PSObject.Properties.Name -contains 'Status') -and $x.Status -and $x.Status -ne 'Success') { } else { $x.Latency }
            }
            elseif ($x.PSObject.Properties['Reply'] -and $x.Reply) { if ($x.Reply.Status -eq 'Success') { $x.Reply.RoundtripTime } }
        }
        $recv = @($lat).Count
        $lossPct = [math]::Round((($count - $recv) / $count) * 100, 1)
        $avg = $null; $max = $null
        if ($recv -gt 0) { $m = $lat | Measure-Object -Average -Maximum; $avg = [math]::Round($m.Average, 1); $max = $m.Maximum }
        return @{ LossPct = $lossPct; AvgMs = $avg; MaxMs = $max; Reachable = ($recv -gt 0) }
    }

    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem

    # --- Rede: config, tipo, pings, DNS, VPN, proxy ---
    $net = @{}
    $ipcfg = safe 'ipconfig' { Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.NetAdapter.Status -eq 'Up' } }
    $ifaces = @(); $hasIp = $false; $gwAddr = $null
    foreach ($c in @($ipcfg)) {
        $ipv4 = ($c.IPv4Address.IPAddress) -join ', '
        if ($ipv4 -and $ipv4 -notmatch '^169\.254') { $hasIp = $true }
        $gw = $c.IPv4DefaultGateway.NextHop
        if ($gw -and -not $gwAddr) { $gwAddr = $gw }
        $dns = ($c.DNSServer | Where-Object AddressFamily -eq 2 | Select-Object -ExpandProperty ServerAddresses) -join ', '
        $ifaces += @{ Alias = $c.InterfaceAlias; IPv4 = $ipv4; Gateway = $gw; Dns = $dns }
    }
    $wifiPct = $null; $connType = 'Cabo'
    $wlan = safe 'wlan' { netsh wlan show interfaces 2>$null }
    if ($wlan) {
        $txt = ($wlan -join "`n")
        if ($txt -match '(?im)^\s*(Sinal|Signal)\s*:\s*(\d+)\s*%') { $wifiPct = [int]$Matches[2]; $connType = 'WiFi' }
    }
    $net['NetIfaces'] = $ifaces
    $net['HasValidIp'] = $hasIp
    $net['WifiSignalPct'] = $wifiPct
    $net['ConnType'] = $connType
    $net['Gateway'] = safe 'ping-gw' { Ping-Stats $gwAddr }
    $net['Internal'] = safe 'ping-int' { Ping-Stats $InternalIp }
    $net['Internet'] = safe 'ping-net' { Ping-Stats $InternetIp }
    $net['DnsInternalOk'] = if ($InternalDnsName) { [bool](safe 'dns-int' { @(Resolve-DnsName -Name $InternalDnsName -Type A -QuickTimeout -ErrorAction SilentlyContinue).Count -gt 0 }) } else { $null }
    $net['DnsExternalOk'] = [bool](safe 'dns-ext' { @(Resolve-DnsName -Name $ExternalDnsName -Type A -QuickTimeout -ErrorAction SilentlyContinue).Count -gt 0 })
    $net['Vpn'] = @(safe 'vpn' { Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'VPN|WireGuard|OpenVPN|AnyConnect|GlobalProtect|FortiClient' } | ForEach-Object { @{ Name = $_.Name; Desc = $_.InterfaceDescription } } })

    # --- Disco ---
    $disks = @(safe 'disks' {
            Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
                @{ Drive = $_.DeviceID
                    SizeGB = [math]::Round($_.Size / 1GB, 1)
                    FreeGB = [math]::Round($_.FreeSpace / 1GB, 1)
                    FreePct = if ($_.Size -gt 0) { [math]::Round($_.FreeSpace / $_.Size * 100, 1) } else { 0 } }
            }
        })

    # --- Reboot pendente ---
    $reboot = [bool](safe 'reboot' {
            $k = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
            $p = @($k | Where-Object { Test-Path $_ }).Count -gt 0
            $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
            $p -or [bool]$pfro
        })

    # --- Antivirus ---
    $av = @(safe 'av' {
            Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object {
                @{ Name = $_.displayName; RealTime = (($_.productState -band 0x1000) -ne 0); Updated = (($_.productState -band 0x10) -eq 0) }
            }
        })

    # --- Startup / Temp ---
    $startup = @(safe 'startup' { Get-CimInstance Win32_StartupCommand | Select-Object -First 20 | ForEach-Object { @{ Name = $_.Name; Command = $_.Command; Location = $_.Location } } })
    $temps = @(safe 'temp' {
            foreach ($p in @($env:TEMP, 'C:\Windows\Temp')) {
                if (Test-Path $p) {
                    $sz = (Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                    @{ Path = $p; SizeMB = [math]::Round(($sz / 1MB), 1) }
                }
            }
        })

    # --- Impressora ---
    $spooler = safe 'spooler' { (Get-Service -Name Spooler -ErrorAction SilentlyContinue).Status.ToString() }
    $printers = @(safe 'printers' {
            $def = (Get-CimInstance Win32_Printer -Filter 'Default=TRUE' -ErrorAction SilentlyContinue).Name
            Get-Printer -ErrorAction SilentlyContinue | ForEach-Object { @{ Name = $_.Name; Driver = $_.DriverName; Port = $_.PortName; Status = "$($_.PrinterStatus)"; IsDefault = ($_.Name -eq $def) } }
        })
    $jobs = @(safe 'printjobs' {
            Get-Printer -ErrorAction SilentlyContinue | ForEach-Object { Get-PrintJob -PrinterName $_.Name -ErrorAction SilentlyContinue } |
                ForEach-Object { @{ Printer = $_.PrinterName; Doc = $_.DocumentName; Status = "$($_.JobStatus)" } }
        })

    # --- Office ---
    $office = safe 'office' {
        foreach ($cp in @('HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration')) {
            if (Test-Path $cp) { (Get-ItemProperty $cp).VersionToReport; break }
        }
    }
    $outlook = [bool](safe 'outlook' { @(Get-Process -Name OUTLOOK -ErrorAction SilentlyContinue).Count -gt 0 })
    $mail = @(safe 'mail' { @{ Host = $MailHost; Port = $MailPort; Ok = [bool](Test-NetConnection -ComputerName $MailHost -Port $MailPort -InformationLevel Quiet -WarningAction SilentlyContinue) } })

    # --- Processos ---
    $topMem = @(safe 'topmem' { Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 | ForEach-Object { @{ Name = $_.Name; Id = $_.Id; WsMB = [math]::Round($_.WorkingSet64 / 1MB, 0) } } })
    $topCpu = @(safe 'topcpu' { Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | ForEach-Object { @{ Name = $_.Name; Id = $_.Id; CpuS = [math]::Round(($_.CPU), 1) } } })

    # --- Erros / BSOD / reinicio ---
    $sysErr = @(safe 'syserr' { Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = (Get-Date).AddHours(-48) } -ErrorAction SilentlyContinue | Select-Object -First 15 | ForEach-Object { @{ Time = "$($_.TimeCreated)"; Id = $_.Id; Level = "$($_.LevelDisplayName)"; Provider = $_.ProviderName; Msg = (($_.Message -split "`n")[0]) } } })
    $appErr = @(safe 'apperr' { Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2; StartTime = (Get-Date).AddHours(-48) } -ErrorAction SilentlyContinue | Select-Object -First 15 | ForEach-Object { @{ Time = "$($_.TimeCreated)"; Id = $_.Id; Level = "$($_.LevelDisplayName)"; Provider = $_.ProviderName; Msg = (($_.Message -split "`n")[0]) } } })
    $bsod = @(safe 'bsod' { Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = (Get-Date).AddDays(-30) } -ErrorAction SilentlyContinue | ForEach-Object { @{ Time = "$($_.TimeCreated)"; Msg = (($_.Message -split "`n")[0]) } } })

    return @{
        CollectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        LoggedUser     = $cs.UserName
        Manufacturer   = $cs.Manufacturer
        Model          = $cs.Model
        Serial         = (Get-CimInstance Win32_BIOS).SerialNumber
        LastBoot       = "$($os.LastBootUpTime)"
        UptimeDays     = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
        RebootPending  = $reboot
        RamTotalGB     = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        RamFreeGB      = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
        RamUsedPct     = [math]::Round(100 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize * 100), 1)
        CpuName        = ((Get-CimInstance Win32_Processor).Name -join '; ')
        CpuLoadPct     = [math]::Round(((Get-CimInstance Win32_Processor).LoadPercentage | Measure-Object -Average).Average, 1)
        Disks          = $disks
        TopMem         = $topMem
        TopCpu         = $topCpu
        Antivirus      = $av
        Startup        = $startup
        TempSizes      = $temps
        SpoolerStatus  = $spooler
        Printers       = $printers
        PrintJobs      = $jobs
        OfficeVersion  = $office
        OutlookRunning = $outlook
        MailConnectivity = $mail
        SysErrors      = $sysErr
        AppErrors      = $appErr
        Bsod           = $bsod
        Net            = $net
        CollectErrors  = @($errs)
    }
}

# ------------------------------------------------------------------- Main ----
# -Preview COM -Hostname = smoke test puro (WinRM + relatorio), sem tocar na API GLPI (dispensa tokens).
$needGlpi = (-not $Preview) -or (-not $Hostname)
if ($needGlpi) { $script:Cfg = Get-GlpiConfig -Path $ConfigPath }
# Alvos de rede especificos do ambiente vem da config (fora do codigo, gitignored) se nao passados por parametro.
if ($script:Cfg) {
    if (-not $InternalIp) { $InternalIp = $script:Cfg.InternalIp }
    if (-not $InternalDnsName) { $InternalDnsName = $script:Cfg.InternalDnsName }
}

if ($SkipCertCheck) {
    if (-not ([System.Management.Automation.PSTypeName]'DiagTrustAll').Type) {
        Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class DiagTrustAll : ICertificatePolicy { public bool CheckValidationResult(ServicePoint sp, X509Certificate c, WebRequest r, int p){return true;} }
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object DiagTrustAll
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if ($needGlpi) { Connect-Glpi }
try {
    # 1. Resolver hostname
    $target = $Hostname
    if (-not $target) {
        Write-Verbose "Sem -Hostname; tentando resolver pelo solicitante do chamado $TicketId..."
        $target = Resolve-HostnameFromTicket -Id $TicketId
    }
    if (-not $target) {
        $msg = "Nao foi possivel determinar a maquina do chamado $TicketId (inventario vazio ou sem vinculo)."
        if ($Auto) {
            # modo poller: posta a nota e sai limpo (return -> finally/Disconnect roda -> exit 0)
            $eW = Get-DiagEmoji 'wrench'
            $html = "<b>$eW Diagnostico automatico &middot; $(Get-Date -Format 'dd/MM HH:mm') &middot; ipe.ia</b><br>$msg<br>"
            Add-TicketDiagnostico -Id $TicketId -Html $html | Out-Null
            Write-Host $msg
            return
        }
        throw "$msg Rode com -Hostname NOME."
    }
    Write-Host "Alvo: $target (chamado #$TicketId)"

    # 2. Alcance / WinRM
    $online = Test-Connection -ComputerName $target -Count 2 -Quiet -ErrorAction SilentlyContinue
    $winrmOk = $false
    try { $null = Test-WSMan -ComputerName $target -Authentication Default -ErrorAction Stop; $winrmOk = $true } catch { $winrmOk = $false }

    $timeText = (Get-Date -Format 'dd/MM HH:mm')

    if (-not $winrmOk) {
        $eW = Get-DiagEmoji 'wrench'; $eR = Get-DiagEmoji 'red'
        $state = if ($online) { 'responde ao ping mas WinRM indisponivel (estacao sem GPO WinRM?)' } else { 'nao responde (desligada / fora da rede)' }
        $html = "<b>$eW Diagnostico automatico &mdash; $target &middot; $timeText &middot; ipe.ia</b><br><br>$eR Nao foi possivel diagnosticar: a maquina $state.<br>"
        if ($Preview) { $html } else { Add-TicketDiagnostico -Id $TicketId -Html $html | Out-Null; Write-Host "Acompanhamento (indisponivel) postado no #$TicketId." }
        return
    }

    # 3. Coleta read-only
    Write-Host "Coletando (read-only) via WinRM..."
    $raw = Invoke-Command -ComputerName $target -ScriptBlock $CollectScript `
        -ArgumentList $InternalIp, $InternalDnsName, $ExternalDnsName, $InternetIp, $MailHost, $MailPort
    $raw['Hostname'] = $target

    # 4. Derivar veredito de rede + combinar
    $netStats = $raw['Net']
    $verdict = Get-NetworkVerdict -Net $netStats
    $network = @{
        Gateway       = (Get-Prop $netStats 'Gateway' $null)
        Internal      = (Get-Prop $netStats 'Internal' $null)
        Internet      = (Get-Prop $netStats 'Internet' $null)
        WifiSignalPct = (Get-Prop $netStats 'WifiSignalPct' $null)
        Level         = $verdict.Level
        Verdict       = $verdict.Verdict
        Detail        = $verdict.Detail
    }
    $raw['Network'] = $network

    # 5. Achados + relatorio
    $findings = Get-Findings -Data $raw
    $html = New-ReportHtml -Data $raw -Findings $findings -Network $network -Meta @{ Hostname = $target; TimeText = $timeText }

    # 6. Postar (ou preview)
    if ($Preview) {
        Write-Host "----- PREVIEW (nao postado) -----"
        $html
    }
    else {
        $r = Add-TicketDiagnostico -Id $TicketId -Html $html
        Write-Host "Acompanhamento postado no #$TicketId (id=$(Get-Prop $r 'id' '?'))."
    }
}
finally {
    Disconnect-Glpi
}
