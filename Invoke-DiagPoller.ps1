#requires -Version 5.1
<#
.SYNOPSIS
    Poller da ponte de orquestracao (Fase 2). Roda NO DC, agendado a cada ~1 min, como Domain Admin.
.DESCRIPTION
    Busca no GLPI (conta ipe.ia) TicketTasks a-fazer (state=1) com o marcador [IPEIA-DIAG] criadas
    nas ultimas N horas; para cada uma roda o motor Diagnostico-GLPI.ps1 -Auto (processo-filho,
    read-only) e marca a tarefa conforme o exit code:
      exit 0  -> feita (concluido)
      exit !=0 sob o limite -> deixa a-fazer (retry no proximo ciclo), incrementa contador
      exit !=0 no limite    -> feita com falha persistente (anti-veneno)
    Lock global (mutex): so um poller por vez (um ciclo pode passar de 1 min).
    Read-only na estacao e garantido pelo proprio motor; aqui so ha leitura/gestao de fila no GLPI.
.NOTES
    O motor e chamado como PROCESSO-FILHO (Start-Process) para que seu 'exit'/'return' nao afete o
    poller e para ler o ExitCode de verdade. Config (Url/tokens) vem de glpi-config.json na mesma pasta.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'glpi-config.json'),
    [string]$Marker = '[IPEIA-DIAG]',
    [int]$MaxAttempts = 5,
    [int]$WindowHours = 24,
    [switch]$SkipCertCheck   # ignora TLS (uso fora do dominio/teste; no DC a CA e confiavel). Repassado ao motor.
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src\GlpiDiagnostico.psm1') -Force

$logFile = Join-Path $PSScriptRoot 'poller.log'
function Write-Log([string]$m) { "$([DateTime]::Now.ToString('s'))  $m" | Add-Content -Path $logFile -Encoding UTF8 }

# --- Lock global: um poller por vez ---
$mtx = New-Object System.Threading.Mutex($false, 'Global\IpeIaDiagPoller')
if (-not $mtx.WaitOne(0)) { Write-Log 'ciclo anterior ainda ativo; saindo'; return }

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ($SkipCertCheck -and -not ([System.Management.Automation.PSTypeName]'PollerTrustAll').Type) {
        Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class PollerTrustAll : ICertificatePolicy { public bool CheckValidationResult(ServicePoint sp, X509Certificate c, WebRequest r, int p){return true;} }
"@
    }
    if ($SkipCertCheck) { [System.Net.ServicePointManager]::CertificatePolicy = New-Object PollerTrustAll }
    $c = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    $base = "$(($c.Url).TrimEnd('/'))/apirest.php"
    $app = $c.AppToken; $usr = $c.UserToken
    $enginePath = Join-Path $PSScriptRoot 'Diagnostico-GLPI.ps1'

    $ih = @{ 'Content-Type' = 'application/json'; 'App-Token' = $app; 'Authorization' = "user_token $usr" }
    $session = (Invoke-RestMethod -Uri "$base/initSession" -Headers $ih -Method Get -TimeoutSec 20).session_token
    $sh = @{ 'Content-Type' = 'application/json'; 'App-Token' = $app; 'Session-Token' = $session }

    try {
        # Todas as tarefas a-fazer (state field = 7, valor 1). Marcador e janela filtrados no cliente (robusto).
        $uri = "$base/search/TicketTask?criteria[0][field]=7&criteria[0][searchtype]=equals&criteria[0][value]=1&forcedisplay[0]=8&range=0-99"
        $res = Invoke-RestMethod -Uri $uri -Headers $sh -Method Get -TimeoutSec 30
        $rows = @(Get-Prop $res 'data' @())
        Write-Log "ciclo: $($rows.Count) tarefa(s) a-fazer no total"
        $cutoff = (Get-Date).AddHours(-$WindowHours)

        foreach ($row in $rows) {
            $taskId = [int](Get-Prop $row '8' 0)
            if ($taskId -le 0) { continue }
            $task = Invoke-RestMethod -Uri "$base/TicketTask/$taskId" -Headers $sh -Method Get -TimeoutSec 20
            $content = [string](Get-Prop $task 'content' '')
            if ($content -notlike "*$Marker*") { continue }                       # nao e nosso
            if ([int](Get-Prop $task 'state' 0) -ne 1) { continue }               # ja saiu de a-fazer
            $dateStr = [string](Get-Prop $task 'date' '')
            $dt = [datetime]::MinValue; [void][datetime]::TryParse($dateStr, [ref]$dt)
            if ($dt -ne [datetime]::MinValue -and $dt -lt $cutoff) { Write-Log "task $taskId fora da janela ($dateStr); ignorando"; continue }

            $ticketId = [int](Get-Prop $task 'tickets_id' 0)
            if ($ticketId -le 0) { Write-Log "task $taskId sem tickets_id; pulando"; continue }
            $attempts = 1; if ($content -match '\[att=(\d+)\]') { $attempts = [int]$Matches[1] + 1 }
            Write-Log "task $taskId ticket $ticketId tentativa $attempts -> rodando motor"

            # motor como PROCESSO-FILHO (isola exit/return; le ExitCode)
            $pargs = @('-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $enginePath, '-TicketId', "$ticketId", '-Auto', '-ConfigPath', $ConfigPath)
            if ($SkipCertCheck) { $pargs += '-SkipCertCheck' }
            $exit = (Start-Process powershell.exe -ArgumentList $pargs -Wait -PassThru -NoNewWindow).ExitCode
            $action = Get-PollerAction -ExitCode $exit -Attempts $attempts -MaxAttempts $MaxAttempts

            $stamp = [DateTime]::Now.ToString('g')
            switch ($action) {
                'done'   { $newContent = "$content`n[IPEIA-DIAG-OK] concluido $stamp"; $newState = 2 }
                'giveup' { $newContent = "$content`n[IPEIA-DIAG-FALHA] desisti apos $attempts tentativas ($stamp)"; $newState = 2 }
                default  { $newContent = (($content -replace '\s*\[att=\d+\]', '') + " [att=$attempts]"); $newState = 1 }
            }
            $body = @{ input = @{ id = $taskId; state = $newState; content = $newContent } }
            $bytes = [Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 6))
            $ph = @{ 'Content-Type' = 'application/json; charset=utf-8'; 'App-Token' = $app; 'Session-Token' = $session }
            Invoke-RestMethod -Uri "$base/TicketTask/$taskId" -Headers $ph -Method Put -Body $bytes -TimeoutSec 20 | Out-Null
            Write-Log "task $taskId ticket $ticketId exit=$exit -> $action (state=$newState)"
        }
    }
    finally { try { Invoke-RestMethod -Uri "$base/killSession" -Headers $sh -Method Get -TimeoutSec 10 | Out-Null } catch {} }
}
catch { Write-Log "ERRO poller: $($_.Exception.Message)" }
finally { $mtx.ReleaseMutex(); $mtx.Dispose() }
