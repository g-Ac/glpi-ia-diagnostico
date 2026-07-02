#requires -Version 5.1
<#
    GlpiDiagnostico.psm1  —  Logica PURA do diagnostico Fase 2a.

    Todas as funcoes recebem dados JA coletados (hashtable/pscustomobject) e
    devolvem objetos ou strings. NENHUMA faz rede, WinRM ou chamada de API.
    Isso mantem a regra de negocio 100% testavel em Pester sem tocar em
    maquina/servidor real. A coleta (Invoke-Command) e o envio (Invoke-RestMethod)
    ficam no orquestrador Diagnostico-GLPI.ps1.
#>

Set-StrictMode -Version Latest

# Emojis como ENTIDADES HTML NUMERICAS (ASCII puro) — a prova de recodificacao no
# transporte (JSON/HTTP em PS5.1 perde caracteres astrais); o navegador renderiza o emoji.
$script:Emoji = @{
    red    = '&#128308;'  # circulo vermelho  U+1F534
    yellow = '&#128993;'  # circulo amarelo   U+1F7E1
    green  = '&#128994;'  # circulo verde     U+1F7E2
    wrench = '&#128295;'  # chave de boca     U+1F527
    warn   = '&#9888;'    # aviso             U+26A0
    net    = '&#127760;'  # globo             U+1F310
}

function Get-DiagEmoji {
    <# Devolve o emoji do nivel (green/yellow/red) ou de um rotulo especial. #>
    param([Parameter(Mandatory)][string]$Key)
    if ($script:Emoji.ContainsKey($Key)) { return $script:Emoji[$Key] }
    return ''
}

function Get-Prop {
    <# Leitura defensiva de propriedade/chave: tolera hashtable, pscustomobject,
       $null e chave ausente (evita explodir sob Set-StrictMode). #>
    param($Obj, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($null -eq $Obj) { return $Default }
    if ($Obj -is [System.Collections.IDictionary]) {
        if ($Obj.Contains($Name)) { return $Obj[$Name] }
        return $Default
    }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $Default
}

function ConvertTo-Gigabytes {
    <# Conversao pura bytes -> GB arredondado. #>
    param([Parameter(Mandatory)][double]$Bytes, [int]$Decimals = 1)
    return [math]::Round($Bytes / 1GB, $Decimals)
}

function Test-ThresholdBreach {
    <# Compara um valor com um limite. $null nunca dispara (return $false). #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Value,
        [Parameter(Mandatory)][ValidateSet('lt', 'le', 'gt', 'ge')][string]$Operator,
        [Parameter(Mandatory)][double]$Limit
    )
    if ($null -eq $Value) { return $false }
    $v = [double]$Value
    switch ($Operator) {
        'lt' { return ($v -lt $Limit) }
        'le' { return ($v -le $Limit) }
        'gt' { return ($v -gt $Limit) }
        'ge' { return ($v -ge $Limit) }
    }
}

function Get-DefaultThresholds {
    <# Limites que definem um "achado" (fora do normal). Ajustaveis. #>
    return @{
        DiskFreePctMin       = 10      # disco livre < 10%  -> achado
        DiskFreeGbMin        = 10      # ou livre < 10 GB   -> achado
        RamFreePctMin        = 10      # RAM livre < 10%    -> achado
        CpuPctMax            = 85      # CPU > 85%          -> achado
        UptimeDaysMax        = 7       # sem reiniciar > 7d -> achado
        LossPctMax           = 2       # perda > 2%         -> achado
        InternetLatencyMsMax = 150     # latencia internet > 150ms -> achado
        WifiPctMin           = 50      # sinal Wi-Fi < 50%  -> achado
        TempMbMax            = 5120    # temp > 5 GB        -> achado
    }
}

function New-Finding {
    param([string]$Level, [string]$Category, [string]$Message)
    return [pscustomobject]@{ Level = $Level; Category = $Category; Message = $Message }
}

function Get-NetworkVerdict {
    <#
      Veredito determinstico de rede a partir de estatisticas JA coletadas.
      -Net: objeto com HasValidIp, WifiSignalPct, DnsExternalOk e, por alvo,
       Gateway/Internal/Internet cada um @{ LossPct; AvgMs }.
      Devolve @{ Level; Verdict; Detail }.
    #>
    param(
        [Parameter(Mandatory)]$Net,
        $Thresholds
    )
    if (-not $Thresholds) { $Thresholds = Get-DefaultThresholds }

    $hasIp   = Get-Prop $Net 'HasValidIp' $true
    $wifi    = Get-Prop $Net 'WifiSignalPct' $null
    $gw      = Get-Prop $Net 'Gateway'  $null
    $inet    = Get-Prop $Net 'Internet' $null
    $dnsExt  = Get-Prop $Net 'DnsExternalOk' $true

    $gwLoss   = [double](Get-Prop $gw   'LossPct' 100)
    $inetLoss = [double](Get-Prop $inet 'LossPct' 100)
    $inetAvg  = Get-Prop $inet 'AvgMs' $null

    $mk = { param($lvl, $txt, $det) [pscustomobject]@{ Level = $lvl; Verdict = $txt; Detail = $det } }

    if (-not $hasIp) {
        return (& $mk 'red' 'Sem rede: placa ou DHCP' 'Sem IP valido (169.254.x ou ausente)')
    }
    if ($null -eq $gw -or $gwLoss -ge 100) {
        return (& $mk 'red' 'Caiu a rede local (cabo/Wi-Fi/switch)' '100% de perda para o gateway')
    }
    if ($null -eq $inet -or $inetLoss -ge 100) {
        return (& $mk 'red' 'Sem internet (provedor/saida/firewall)' 'Gateway responde, internet nao')
    }
    if (-not $dnsExt) {
        return (& $mk 'yellow' 'Problema de DNS' 'Chega na internet por IP mas nao resolve nomes')
    }

    $causes = @()
    if (Test-ThresholdBreach $inetAvg 'gt' $Thresholds.InternetLatencyMsMax) {
        $causes += ('internet lenta ({0}ms)' -f [int]$inetAvg)
    }
    $partial = @(@($gwLoss, [double](Get-Prop (Get-Prop $Net 'Internal' $null) 'LossPct' 0), $inetLoss) |
        Where-Object { $_ -gt $Thresholds.LossPctMax -and $_ -lt 100 })
    if ($partial.Count -gt 0) {
        $causes += ('perda de pacote ({0}%)' -f ([int]($partial | Measure-Object -Maximum).Maximum))
    }
    if (Test-ThresholdBreach $wifi 'lt' $Thresholds.WifiPctMin) {
        $causes += ('Wi-Fi fraco ({0}%)' -f [int]$wifi)
    }

    if ($causes.Count -gt 0) {
        return (& $mk 'yellow' 'Internet lenta/instavel' ($causes -join ' - '))
    }
    return (& $mk 'green' 'Rede OK' '')
}

function Get-Findings {
    <#
      Aplica os limites ao objeto de dados coletado e devolve a lista de achados
      (fora do normal). $Data e o objeto agregado montado pelo orquestrador.
    #>
    param(
        [Parameter(Mandatory)]$Data,
        $Thresholds
    )
    if (-not $Thresholds) { $Thresholds = Get-DefaultThresholds }
    $out = New-Object System.Collections.Generic.List[object]

    # --- Disco ---
    foreach ($d in @(Get-Prop $Data 'Disks' @())) {
        $drive   = Get-Prop $d 'Drive' '?'
        $freePct = Get-Prop $d 'FreePct' $null
        $freeGb  = Get-Prop $d 'FreeGB' $null
        if ((Test-ThresholdBreach $freePct 'lt' $Thresholds.DiskFreePctMin) -or
            (Test-ThresholdBreach $freeGb 'lt' $Thresholds.DiskFreeGbMin)) {
            $out.Add((New-Finding 'red' 'Disco' ("Disco {0} com {1}% livre ({2} GB)" -f $drive, $freePct, $freeGb)))
        }
    }

    # --- RAM ---
    $ramFreePct = Get-Prop $Data 'RamFreePct' $null
    if ($null -eq $ramFreePct) {
        $used = Get-Prop $Data 'RamUsedPct' $null
        if ($null -ne $used) { $ramFreePct = 100 - [double]$used }
    }
    if (Test-ThresholdBreach $ramFreePct 'lt' $Thresholds.RamFreePctMin) {
        $out.Add((New-Finding 'red' 'Memoria' ("RAM com apenas {0}% livre" -f [math]::Round([double]$ramFreePct, 0))))
    }

    # --- CPU ---
    $cpu = Get-Prop $Data 'CpuLoadPct' $null
    if (Test-ThresholdBreach $cpu 'gt' $Thresholds.CpuPctMax) {
        $out.Add((New-Finding 'yellow' 'CPU' ("CPU alta: {0}%" -f [math]::Round([double]$cpu, 0))))
    }

    # --- Uptime / reboot pendente ---
    $uptime = Get-Prop $Data 'UptimeDays' $null
    if (Test-ThresholdBreach $uptime 'gt' $Thresholds.UptimeDaysMax) {
        $out.Add((New-Finding 'yellow' 'Reinicio' ("Sem reiniciar ha {0} dias" -f [math]::Round([double]$uptime, 0))))
    }
    if ([bool](Get-Prop $Data 'RebootPending' $false)) {
        $out.Add((New-Finding 'yellow' 'Reinicio' 'Reinicializacao pendente (update aguardando reboot)'))
    }

    # --- Rede: perda / latencia / Wi-Fi (do proprio veredito) ---
    $net = Get-Prop $Data 'Network' $null
    if ($null -ne $net) {
        $wifi = Get-Prop $net 'WifiSignalPct' $null
        if (Test-ThresholdBreach $wifi 'lt' $Thresholds.WifiPctMin) {
            $out.Add((New-Finding 'yellow' 'Rede' ("Sinal Wi-Fi fraco: {0}%" -f [int]$wifi)))
        }
        foreach ($tgt in 'Gateway', 'Internal', 'Internet') {
            $t = Get-Prop $net $tgt $null
            $loss = Get-Prop $t 'LossPct' $null
            if (Test-ThresholdBreach $loss 'gt' $Thresholds.LossPctMax) {
                $lvl = 'yellow'; if ([double]$loss -ge 100) { $lvl = 'red' }
                $out.Add((New-Finding $lvl 'Rede' ("Perda de pacote {0}% ({1})" -f [int]$loss, $tgt)))
            }
        }
        $inetAvg = Get-Prop (Get-Prop $net 'Internet' $null) 'AvgMs' $null
        if (Test-ThresholdBreach $inetAvg 'gt' $Thresholds.InternetLatencyMsMax) {
            $out.Add((New-Finding 'yellow' 'Rede' ("Latencia alta para a internet: {0}ms" -f [int]$inetAvg)))
        }
    }

    # --- Antivirus --- A maquina esta protegida se QUALQUER AV registrado tem real-time on.
    #     Nao marcar vermelho so porque o Defender esta inativo quando ha outro AV ativo
    #     (ex.: Kaspersky assume e o Defender fica passivo) -> evita falso-positivo na frota.
    $avs = @(@(Get-Prop $Data 'Antivirus' @()) | Where-Object { $null -ne $_ })
    if ($avs.Count -gt 0) {
        $active = @($avs | Where-Object { [bool](Get-Prop $_ 'RealTime' $false) })
        if ($active.Count -eq 0) {
            $names = ($avs | ForEach-Object { Get-Prop $_ 'Name' 'AV' }) -join ', '
            $out.Add((New-Finding 'red' 'Antivirus' ("Nenhum antivirus com protecao em tempo real ativa ({0})" -f $names)))
        }
        else {
            foreach ($av in $active) {
                if (-not [bool](Get-Prop $av 'Updated' $true)) {
                    $out.Add((New-Finding 'yellow' 'Antivirus' ("{0}: assinaturas desatualizadas" -f (Get-Prop $av 'Name' 'Antivirus'))))
                }
            }
        }
    }

    # --- Impressora: spooler / fila ---
    $spooler = Get-Prop $Data 'SpoolerStatus' $null
    if ($null -ne $spooler -and $spooler -ne 'Running') {
        $out.Add((New-Finding 'yellow' 'Impressora' ("Spooler de impressao {0}" -f $spooler)))
    }
    $jammed = @(Get-Prop $Data 'PrintJobs' @()) | Where-Object {
        $s = Get-Prop $_ 'Status' ''
        $s -match 'Error|Blocked|Paused'
    }
    if (@($jammed).Count -gt 0) {
        $out.Add((New-Finding 'yellow' 'Impressora' ("Fila de impressao travada ({0} job(s) com erro)" -f @($jammed).Count)))
    }

    # --- Temp grande ---
    foreach ($t in @(Get-Prop $Data 'TempSizes' @())) {
        $mb = Get-Prop $t 'SizeMB' $null
        if (Test-ThresholdBreach $mb 'gt' $Thresholds.TempMbMax) {
            $out.Add((New-Finding 'yellow' 'Lentidao' ("Pasta temporaria grande: {0} ({1} MB)" -f (Get-Prop $t 'Path' '?'), [int]$mb)))
        }
    }

    # --- Erros / BSOD ---
    $bsod = @(@(Get-Prop $Data 'Bsod' @()) | Where-Object { $null -ne $_ })
    if ($bsod.Count -gt 0) {
        $out.Add((New-Finding 'red' 'Erros' ("Tela azul (BSOD) recente: {0} ocorrencia(s)" -f $bsod.Count)))
    }
    $sysErr = @(Get-Prop $Data 'SysErrors' @())
    $appErr = @(Get-Prop $Data 'AppErrors' @())
    $critCount = @($sysErr + $appErr | Where-Object { (Get-Prop $_ 'Level' '') -match 'Cr[ií]tic' }).Count
    if ($critCount -gt 0) {
        $out.Add((New-Finding 'yellow' 'Erros' ("{0} erro(s) critico(s) no log nas ultimas 48h" -f $critCount)))
    }

    return @($out.ToArray() | Where-Object { $null -ne $_ })
}

function Get-OverallLevel {
    <# Nivel geral (pior achado): red > yellow > green. #>
    param($Findings)
    $arr = @($Findings)
    if ($arr | Where-Object { (Get-Prop $_ 'Level' '') -eq 'red' })    { return 'red' }
    if ($arr | Where-Object { (Get-Prop $_ 'Level' '') -eq 'yellow' }) { return 'yellow' }
    return 'green'
}

function New-GlpiFollowupBody {
    <# Monta o corpo do POST /ITILFollowup. Puro: nao executa a chamada. #>
    param(
        [Parameter(Mandatory)][int]$TicketId,
        [Parameter(Mandatory)][string]$Html,
        [ValidateSet(0, 1)][int]$IsPrivate = 0
    )
    return @{
        input = @{
            itemtype   = 'Ticket'
            items_id   = $TicketId
            content    = $Html
            is_private = $IsPrivate
        }
    }
}

function ConvertTo-HtmlEncoded {
    <# Escapa < > & para nao quebrar o HTML do relatorio com dados da maquina. #>
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;')
}

function New-ReportHtml {
    <#
      Monta o HTML do acompanhamento (layout: Resumo + Achados + Rede + Dados).
      Usa apenas tags do allowlist do sanitizer do GLPI (b, br, hr, ul/li,
      table/tr/td/th com border). Puro: recebe dados e devolve string.
    #>
    param(
        [Parameter(Mandatory)]$Data,
        $Findings,
        $Network,
        [hashtable]$Meta
    )
    if (-not $Meta) { $Meta = @{} }
    $host_    = Get-Prop $Meta 'Hostname' (Get-Prop $Data 'Hostname' '?')
    $timeText = Get-Prop $Meta 'TimeText' ''
    $eR = Get-DiagEmoji 'red'; $eY = Get-DiagEmoji 'yellow'; $eG = Get-DiagEmoji 'green'
    $eNet = Get-DiagEmoji 'net'; $eW = Get-DiagEmoji 'wrench'; $eA = Get-DiagEmoji 'warn'

    # Defensivo: nunca renderizar achado nulo ou de mensagem vazia (evita "achado-fantasma").
    $findings = @($Findings | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string](Get-Prop $_ 'Message' '')) })
    $overall  = Get-OverallLevel $findings
    $overEmoji = switch ($overall) { 'red' { $eR } 'yellow' { $eY } default { $eG } }

    $lvlEmoji = {
        param($l)
        switch ($l) { 'red' { $eR } 'yellow' { $eY } default { $eG } }
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<b>$eW Diagnostico automatico &mdash; $host_")
    if ($timeText) { [void]$sb.Append(" &middot; $timeText") }
    [void]$sb.Append(" &middot; ipe.ia</b><br>")

    # Resumo
    $nAch = $findings.Count
    [void]$sb.Append("<b>RESUMO:</b> $overEmoji $nAch achado(s)")
    if ($null -ne $Network) {
        $nv = Get-Prop $Network 'Level' 'green'
        [void]$sb.Append(" &middot; $eNet rede: $(& $lvlEmoji $nv) $(ConvertTo-HtmlEncoded (Get-Prop $Network 'Verdict' ''))")
    }
    [void]$sb.Append("<br>")

    # Achados
    if ($nAch -gt 0) {
        [void]$sb.Append("<br><b>$eA ACHADOS (fora do normal)</b><ul>")
        foreach ($f in $findings) {
            $em = & $lvlEmoji (Get-Prop $f 'Level' 'yellow')
            [void]$sb.Append("<li>$em " + (ConvertTo-HtmlEncoded (Get-Prop $f 'Message' '')) + "</li>")
        }
        [void]$sb.Append("</ul>")
    }
    else {
        [void]$sb.Append("<br>$eG Nenhum achado fora do normal.<br>")
    }

    # Rede (linha de veredito)
    if ($null -ne $Network) {
        $nv = Get-Prop $Network 'Level' 'green'
        $det = Get-Prop $Network 'Detail' ''
        [void]$sb.Append("$eNet <b>REDE:</b> $(& $lvlEmoji $nv) " + (ConvertTo-HtmlEncoded (Get-Prop $Network 'Verdict' '')))
        if ($det) { [void]$sb.Append(" (" + (ConvertTo-HtmlEncoded $det) + ")") }
        [void]$sb.Append("<br>")
    }

    # Dados completos
    [void]$sb.Append("<hr><b>Dados completos</b><hr>")

    # Geral
    [void]$sb.Append("<b>Geral</b><br>")
    $ram = "{0} GB total / {1} GB livre" -f (Get-Prop $Data 'RamTotalGB' '?'), (Get-Prop $Data 'RamFreeGB' '?')
    $rows = @(
        @('Usuario logado', (Get-Prop $Data 'LoggedUser' '?')),
        @('Modelo', ("{0} {1}" -f (Get-Prop $Data 'Manufacturer' ''), (Get-Prop $Data 'Model' ''))),
        @('Serie', (Get-Prop $Data 'Serial' '?')),
        @('Uptime', ("{0} dias" -f (Get-Prop $Data 'UptimeDays' '?'))),
        @('Reboot pendente', (& { if (Get-Prop $Data 'RebootPending' $false) { 'Sim' } else { 'Nao' } })),
        @('RAM', $ram),
        @('CPU', ("{0} ({1}%)" -f (Get-Prop $Data 'CpuName' '?'), (Get-Prop $Data 'CpuLoadPct' '?')))
    )
    [void]$sb.Append('<table border="1">')
    foreach ($r in $rows) {
        [void]$sb.Append("<tr><td><b>" + (ConvertTo-HtmlEncoded ([string]$r[0])) + "</b></td><td>" + (ConvertTo-HtmlEncoded ([string]$r[1])) + "</td></tr>")
    }
    [void]$sb.Append('</table>')

    # Discos
    $disks = @(Get-Prop $Data 'Disks' @())
    if ($disks.Count -gt 0) {
        [void]$sb.Append("<br><b>Discos</b><table border=""1""><tr><th>Drive</th><th>Tamanho</th><th>Livre</th><th>% livre</th></tr>")
        foreach ($d in $disks) {
            [void]$sb.Append("<tr><td>$(ConvertTo-HtmlEncoded ([string](Get-Prop $d 'Drive' '?')))</td><td>$(Get-Prop $d 'SizeGB' '?') GB</td><td>$(Get-Prop $d 'FreeGB' '?') GB</td><td>$(Get-Prop $d 'FreePct' '?')%</td></tr>")
        }
        [void]$sb.Append('</table>')
    }

    # Rede detalhe
    if ($null -ne $Network) {
        [void]$sb.Append("<br><b>Rede</b><table border=""1""><tr><th>Alvo</th><th>Perda</th><th>Latencia media</th></tr>")
        foreach ($tgt in 'Gateway', 'Internal', 'Internet') {
            $t = Get-Prop $Network $tgt $null
            if ($null -ne $t) {
                [void]$sb.Append("<tr><td>$tgt</td><td>$(Get-Prop $t 'LossPct' '?')%</td><td>$(Get-Prop $t 'AvgMs' '?') ms</td></tr>")
            }
        }
        [void]$sb.Append('</table>')
        $wifi = Get-Prop $Network 'WifiSignalPct' $null
        if ($null -ne $wifi) { [void]$sb.Append("Wi-Fi: $wifi%<br>") }
    }

    # Top processos (memoria)
    $topMem = @(Get-Prop $Data 'TopMem' @())
    if ($topMem.Count -gt 0) {
        [void]$sb.Append("<br><b>Top processos (memoria)</b><table border=""1""><tr><th>Processo</th><th>MB</th></tr>")
        foreach ($p in $topMem) {
            [void]$sb.Append("<tr><td>$(ConvertTo-HtmlEncoded ([string](Get-Prop $p 'Name' '?')))</td><td>$(Get-Prop $p 'WsMB' '?')</td></tr>")
        }
        [void]$sb.Append('</table>')
    }

    # Antivirus (transparencia: quais AVs e estado)
    $avList = @(Get-Prop $Data 'Antivirus' @())
    if ($avList.Count -gt 0) {
        $avtxt = ($avList | ForEach-Object {
                $st = if ([bool](Get-Prop $_ 'RealTime' $false)) { 'ativo' } else { 'inativo' }
                "{0} ({1})" -f (ConvertTo-HtmlEncoded ([string](Get-Prop $_ 'Name' 'AV'))), $st
            }) -join ' &middot; '
        [void]$sb.Append("<br><b>Antivirus</b><br>$avtxt<br>")
    }

    # Erros (contagem + primeiros)
    $sysErr = @(Get-Prop $Data 'SysErrors' @())
    $appErr = @(Get-Prop $Data 'AppErrors' @())
    [void]$sb.Append("<br><b>Erros (48h)</b><br>System: $($sysErr.Count) &middot; Application: $($appErr.Count)<br>")

    return $sb.ToString()
}

function Get-PollerAction {
    <#
      Decisao pura do poller a partir do exit code do motor e do numero de tentativas.
      'done'   = motor tratou (exit 0) -> marcar tarefa feita.
      'giveup' = erro transiente que ja bateu o limite -> marcar feita com falha (anti-veneno).
      'retry'  = erro transiente sob o limite -> deixar a-fazer pro proximo ciclo.
    #>
    param(
        [Parameter(Mandatory)][int]$ExitCode,
        [int]$Attempts = 1,
        [int]$MaxAttempts = 5
    )
    if ($ExitCode -eq 0) { return 'done' }
    if ($Attempts -ge $MaxAttempts) { return 'giveup' }
    return 'retry'
}

Export-ModuleMember -Function `
    Get-DiagEmoji, Get-Prop, ConvertTo-Gigabytes, Test-ThresholdBreach, `
    Get-DefaultThresholds, New-Finding, Get-NetworkVerdict, Get-Findings, `
    Get-OverallLevel, New-GlpiFollowupBody, ConvertTo-HtmlEncoded, New-ReportHtml, `
    Get-PollerAction
