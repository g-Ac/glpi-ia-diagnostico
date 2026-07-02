# Diagnóstico GLPI — Fase 2a (read-only)

Diagnóstico **somente-leitura** de uma estação Windows, disparado sob demanda pelo técnico,
que posta um relatório organizado como **acompanhamento no chamado** do GLPI.

Roda **no Domain Controller** (sessão Domain Admin), alcança a estação por **WinRM/PS-Remoting**
e fala com o GLPI pela **API REST**. Valores específicos do ambiente (URL, tokens, IP interno,
nome DNS interno) ficam **fora do código**, num `glpi-config.json` (não versionado).

## Arquivos

| Arquivo | Papel |
|---|---|
| `src/GlpiDiagnostico.psm1` | **Lógica pura** (vereditos, limites, achados, HTML). Sem I/O. Testável. |
| `Diagnostico-GLPI.ps1` | **Orquestrador** (I/O): API GLPI + coleta WinRM read-only + monta e posta o relatório. |
| `tests/GlpiDiagnostico.Tests.ps1` | Testes Pester 5 da lógica pura. |

## Guard-rail (Fase 2a)

O `ScriptBlock` remoto contém **exclusivamente** comandos de leitura: `Get-*`, `Test-*`,
`Resolve-*`, `Measure-*`, `Get-CimInstance`, `Get-WinEvent`, `netsh ... show`. **Nenhum**
verbo mutante. Ações que alteram a máquina são a Fase 2b (com confirmação + log).

> **Importante:** WinRM concede acesso admin no alvo. O caráter read-only é garantido pelo
> *conteúdo do script*, não pelo WinRM. Restrinja a origem do WinRM no firewall do endpoint.

## Pré-requisitos

**No DC (onde o script roda):**
- Windows PowerShell 5.1, sessão **Domain Admin** (Kerberos → sem TrustedHosts).
- **WinRM habilitado nas estações** (por GPO ou gestão do endpoint).
- `glpi-config.json` preenchido (ver abaixo).
- CA/TLS do GLPI confiável no DC. Fora do domínio, use `-SkipCertCheck`.

**No GLPI:**
- API REST habilitada e acessível pela URL configurada.
- Conta de serviço com token e permissão de leitura de Computadores + criar acompanhamento.
- **Auto-hostname** depende do **inventário populado** (mapa usuário↔computador). Enquanto vazio,
  use sempre `-Hostname`.

## Configuração

Crie `glpi-config.json` ao lado do script (ou use as variáveis de ambiente equivalentes):

```json
{
  "Url": "https://glpi.suaempresa.com.br",
  "AppToken": "<app_token do cliente de API>",
  "UserToken": "<user_token da conta de serviço>",
  "InternalIp": "<IP de um servidor interno p/ ping, ex. o DC>",
  "InternalDnsName": "<nome interno p/ testar DNS, ex. a URL do GLPI>"
}
```

- `Url`/`AppToken`/`UserToken` — obrigatórios (ou via env `GLPI_PUBLIC_URL`/`GLPI_APP_TOKEN`/`GLPI_USER_TOKEN`).
- `InternalIp`/`InternalDnsName` — **opcionais**; alvos de rede internos p/ o veredito (ping interno + resolução DNS interna). Se ausentes, esses dois checks são pulados.

> ⚠️ O arquivo contém **segredos**. Restrinja o ACL (SIDs, à prova de idioma):
> `icacls glpi-config.json /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F"`.
> Não versionar (já está no `.gitignore`).

## Uso

```powershell
# Com hostname explícito:
.\Diagnostico-GLPI.ps1 -TicketId 1234 -Hostname PC01

# Auto-resolução pelo solicitante do chamado (quando o inventário estiver cheio):
.\Diagnostico-GLPI.ps1 -TicketId 1234

# Smoke test WinRM sem tocar na API (não precisa de tokens):
.\Diagnostico-GLPI.ps1 -TicketId 0 -Hostname PC01 -Preview

# Fora do domínio (CA não confiável):
.\Diagnostico-GLPI.ps1 -TicketId 1234 -Hostname PC01 -SkipCertCheck
```

Parâmetros de rede também aceitos por linha de comando (sobrepõem a config): `-InternalIp`,
`-InternalDnsName`, `-ExternalDnsName` (default `www.microsoft.com`), `-InternetIp` (default
`1.1.1.1`), `-MailHost`/`-MailPort` (default `outlook.office365.com:443`).

## Testes

```powershell
Import-Module Pester -MinimumVersion 5.0.0 -Force
$cfg = New-PesterConfiguration; $cfg.Run.Path = '.\tests'
Invoke-Pester -Configuration $cfg
```

## O que o relatório traz

Cabeçalho + **Resumo** (semáforo 🟢🟡🔴 + veredito de rede) + **Achados** (só o que está fora do
normal, por limites ajustáveis) + **Rede** (perda/latência por alvo, veredito) + **Dados completos**
(geral, discos, top processos, antivírus, erros). Determinístico (não gerado por IA), com apenas
tags de HTML que o sanitizer do GLPI preserva e emojis via entidades numéricas.
