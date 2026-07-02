#requires -Version 5.1
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Testes da logica PURA (GlpiDiagnostico.psm1). Nenhum toca em rede/WinRM/API.
    Rodar:  Invoke-Pester -Path .\tests -Output Detailed
#>

BeforeAll {
    $module = Join-Path $PSScriptRoot '..\src\GlpiDiagnostico.psm1'
    Import-Module $module -Force
}

Describe 'ConvertTo-Gigabytes' {
    It 'converte bytes para GB arredondado' {
        ConvertTo-Gigabytes -Bytes 1073741824 | Should -Be 1
    }
    It 'respeita o numero de casas decimais' {
        ConvertTo-Gigabytes -Bytes 1610612736 -Decimals 2 | Should -Be 1.5
    }
}

Describe 'Test-ThresholdBreach' {
    It 'lt: dispara quando abaixo do limite' {
        Test-ThresholdBreach -Value 4 -Operator lt -Limit 10 | Should -BeTrue
    }
    It 'lt: nao dispara quando no/acima do limite' {
        Test-ThresholdBreach -Value 10 -Operator lt -Limit 10 | Should -BeFalse
    }
    It 'gt: dispara quando acima do limite' {
        Test-ThresholdBreach -Value 90 -Operator gt -Limit 85 | Should -BeTrue
    }
    It 'valor $null nunca dispara' {
        Test-ThresholdBreach -Value $null -Operator lt -Limit 10 | Should -BeFalse
    }
}

Describe 'Get-NetworkVerdict' {

    It 'sem IP valido => vermelho "Sem rede"' {
        $r = Get-NetworkVerdict -Net @{ HasValidIp = $false }
        $r.Level   | Should -Be 'red'
        $r.Verdict | Should -Match 'Sem rede'
    }

    It '100% de perda no gateway => "Caiu a rede local"' {
        $net = @{ HasValidIp = $true; Gateway = @{ LossPct = 100 }; Internet = @{ LossPct = 0; AvgMs = 10 } }
        (Get-NetworkVerdict -Net $net).Verdict | Should -Match 'Caiu a rede local'
    }

    It 'gateway OK mas internet 100% perda => "Sem internet"' {
        $net = @{ HasValidIp = $true; Gateway = @{ LossPct = 0; AvgMs = 2 }; Internet = @{ LossPct = 100 } }
        (Get-NetworkVerdict -Net $net).Verdict | Should -Match 'Sem internet'
    }

    It 'internet por IP OK mas DNS externo falha => "Problema de DNS"' {
        $net = @{ HasValidIp = $true; Gateway = @{ LossPct = 0; AvgMs = 2 }; Internet = @{ LossPct = 0; AvgMs = 20 }; DnsExternalOk = $false }
        (Get-NetworkVerdict -Net $net).Verdict | Should -Match 'DNS'
    }

    It 'tudo responde e rapido => verde "Rede OK"' {
        $net = @{ HasValidIp = $true; Gateway = @{ LossPct = 0; AvgMs = 2 }; Internal = @{ LossPct = 0; AvgMs = 3 }; Internet = @{ LossPct = 0; AvgMs = 18 }; DnsExternalOk = $true; WifiSignalPct = 80 }
        $r = Get-NetworkVerdict -Net $net
        $r.Level   | Should -Be 'green'
        $r.Verdict | Should -Be 'Rede OK'
    }

    It 'latencia internet alta => amarelo "Internet lenta/instavel"' {
        $net = @{ HasValidIp = $true; Gateway = @{ LossPct = 0; AvgMs = 2 }; Internet = @{ LossPct = 0; AvgMs = 220 }; DnsExternalOk = $true }
        $r = Get-NetworkVerdict -Net $net
        $r.Level  | Should -Be 'yellow'
        $r.Detail | Should -Match 'internet lenta'
    }

    It 'Wi-Fi fraco entra como causa da instabilidade' {
        $net = @{ HasValidIp = $true; Gateway = @{ LossPct = 0; AvgMs = 2 }; Internet = @{ LossPct = 5; AvgMs = 30 }; DnsExternalOk = $true; WifiSignalPct = 35 }
        $r = Get-NetworkVerdict -Net $net
        $r.Level  | Should -Be 'yellow'
        $r.Detail | Should -Match 'Wi-Fi fraco'
    }
}

Describe 'Get-Findings' {

    It 'disco quase cheio vira achado vermelho' {
        $data = @{ Disks = @(@{ Drive = 'C:'; SizeGB = 238; FreeGB = 4; FreePct = 2 }) }
        $f = Get-Findings -Data $data
        ($f | Where-Object Category -eq 'Disco').Level | Should -Be 'red'
    }

    It 'disco saudavel nao vira achado' {
        $data = @{ Disks = @(@{ Drive = 'C:'; SizeGB = 238; FreeGB = 120; FreePct = 50 }) }
        (Get-Findings -Data $data | Where-Object Category -eq 'Disco') | Should -BeNullOrEmpty
    }

    It 'reboot pendente vira achado amarelo' {
        $f = Get-Findings -Data @{ RebootPending = $true }
        ($f | Where-Object Category -eq 'Reinicio').Level | Should -Be 'yellow'
    }

    It 'nenhum AV com realtime ativo => achado vermelho' {
        $f = Get-Findings -Data @{ Antivirus = @(@{ Name = 'Defender'; RealTime = $false; Updated = $true }) }
        ($f | Where-Object Category -eq 'Antivirus').Level | Should -Be 'red'
    }

    It 'Defender inativo mas outro AV ativo (Kaspersky) => sem achado de antivirus' {
        $data = @{ Antivirus = @(
                @{ Name = 'Windows Defender'; RealTime = $false; Updated = $true },
                @{ Name = 'Kaspersky Endpoint Security'; RealTime = $true; Updated = $true }
            ) }
        (Get-Findings -Data $data | Where-Object Category -eq 'Antivirus') | Should -BeNullOrEmpty
    }

    It 'CPU alta vira achado amarelo' {
        $f = Get-Findings -Data @{ CpuLoadPct = 95 }
        ($f | Where-Object Category -eq 'CPU').Level | Should -Be 'yellow'
    }

    It 'maquina saudavel nao gera achados' {
        $data = @{
            Disks = @(@{ Drive = 'C:'; FreeGB = 100; FreePct = 45 })
            RamUsedPct = 40; CpuLoadPct = 12; UptimeDays = 2; RebootPending = $false
            Antivirus = @(@{ Name = 'Defender'; RealTime = $true; Updated = $true })
            SpoolerStatus = 'Running'
        }
        @(Get-Findings -Data $data).Count | Should -Be 0
    }

    It 'perda de pacote no gateway vira achado de rede' {
        $data = @{ Network = @{ Gateway = @{ LossPct = 20; AvgMs = 5 } } }
        ($f = Get-Findings -Data $data | Where-Object Category -eq 'Rede') | Should -Not -BeNullOrEmpty
    }

    It 'coleta de AV vazia/nula NAO gera falso-vermelho (borda)' {
        (Get-Findings -Data @{ Antivirus = @($null) } | Where-Object Category -eq 'Antivirus') | Should -BeNullOrEmpty
        (Get-Findings -Data @{ Antivirus = @() } | Where-Object Category -eq 'Antivirus') | Should -BeNullOrEmpty
    }

    It 'Bsod com elemento nulo NAO gera falso "tela azul" (borda)' {
        (Get-Findings -Data @{ Bsod = @($null) } | Where-Object Category -eq 'Erros') | Should -BeNullOrEmpty
    }
}

Describe 'Get-OverallLevel' {
    It 'sem achados => green' {
        Get-OverallLevel @() | Should -Be 'green'
    }
    It 'com um vermelho => red (mesmo tendo amarelos)' {
        $fs = @(
            [pscustomobject]@{ Level = 'yellow' },
            [pscustomobject]@{ Level = 'red' }
        )
        Get-OverallLevel $fs | Should -Be 'red'
    }
    It 'so amarelos => yellow' {
        Get-OverallLevel @([pscustomobject]@{ Level = 'yellow' }) | Should -Be 'yellow'
    }
}

Describe 'New-GlpiFollowupBody' {
    It 'monta o input com itemtype Ticket e items_id' {
        $b = New-GlpiFollowupBody -TicketId 7490 -Html '<b>ola</b>'
        $b.input.itemtype   | Should -Be 'Ticket'
        $b.input.items_id   | Should -Be 7490
        $b.input.content    | Should -Be '<b>ola</b>'
        $b.input.is_private | Should -Be 0
    }
}

Describe 'ConvertTo-HtmlEncoded' {
    It 'escapa caracteres perigosos de HTML' {
        ConvertTo-HtmlEncoded '<script>a & b>' | Should -Be '&lt;script&gt;a &amp; b&gt;'
    }
    It 'null vira string vazia' {
        ConvertTo-HtmlEncoded $null | Should -Be ''
    }
}

Describe 'New-ReportHtml' {

    BeforeAll {
        $script:data = @{
            Hostname = 'PC01'; LoggedUser = 'GRUPO\joao'; Manufacturer = 'Dell'; Model = 'OptiPlex'
            Serial = 'ABC123'; UptimeDays = 12; RebootPending = $true; RamTotalGB = 8; RamFreeGB = 0.5; RamUsedPct = 94
            CpuName = 'i5'; CpuLoadPct = 20
            Disks = @(@{ Drive = 'C:'; SizeGB = 238; FreeGB = 4; FreePct = 2 })
            TopMem = @(@{ Name = 'chrome'; WsMB = 900 })
            SysErrors = @(); AppErrors = @()
        }
        $script:net = Get-NetworkVerdict -Net @{ HasValidIp = $true; Gateway = @{ LossPct = 0; AvgMs = 2 }; Internet = @{ LossPct = 0; AvgMs = 18 }; DnsExternalOk = $true; WifiSignalPct = 78 }
        $script:findings = Get-Findings -Data $script:data
        $script:html = New-ReportHtml -Data $script:data -Findings $script:findings -Network $script:net -Meta @{ Hostname = 'PC01'; TimeText = '01/07 14:32' }
    }

    It 'contem o cabecalho com hostname e ipe.ia' {
        $script:html | Should -Match 'PC01'
        $script:html | Should -Match 'ipe\.ia'
    }
    It 'contem a secao RESUMO e ACHADOS' {
        $script:html | Should -Match 'RESUMO:'
        $script:html | Should -Match 'ACHADOS'
    }
    It 'lista o achado de disco cheio' {
        $script:html | Should -Match 'Disco C:'
    }
    It 'contem a linha de REDE' {
        $script:html | Should -Match 'REDE:'
        $script:html | Should -Match 'Rede OK'
    }
    It 'usa apenas tags do allowlist do GLPI (sem script/style tag)' {
        $script:html | Should -Not -Match '<script'
        $script:html | Should -Match '<table border'
    }

    It 'ignora achados nulos ou de mensagem vazia (anti-fantasma)' {
        $findings = @(
            [pscustomobject]@{ Level = 'red'; Category = 'Disco'; Message = 'Disco cheio' },
            $null,
            [pscustomobject]@{ Level = 'yellow'; Category = 'X'; Message = '' }
        )
        $html = New-ReportHtml -Data @{ Hostname = 'PC' } -Findings $findings -Network $null -Meta @{ Hostname = 'PC' }
        $html | Should -Match 'Disco cheio'
        $html | Should -Match '1 achado'   # conta 1, nao 3
    }
}

Describe 'Get-PollerAction' {
    It 'exit 0 => done' { Get-PollerAction -ExitCode 0 -Attempts 1 -MaxAttempts 5 | Should -Be 'done' }
    It 'exit !=0 sob o limite => retry' { Get-PollerAction -ExitCode 1 -Attempts 1 -MaxAttempts 5 | Should -Be 'retry' }
    It 'exit !=0 no limite => giveup' { Get-PollerAction -ExitCode 1 -Attempts 5 -MaxAttempts 5 | Should -Be 'giveup' }
}
