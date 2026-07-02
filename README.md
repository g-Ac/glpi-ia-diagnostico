# Diagnóstico GLPI — Fase 2a (read-only)

Diagnóstico **somente-leitura** de uma estação Windows, disparado sob demanda pelo
técnico, que posta um relatório organizado como **acompanhamento no chamado** do GLPI.

Faz parte da IA "ipe.ia". Roda **no Domain Controller** (sessão Domain Admin), alcança a
estação por **WinRM/PS-Remoting** e fala com o GLPI pela **API REST** (conta `ipe.ia`).

## Arquivos

| Arquivo | Papel |
|---|---|
| `src/GlpiDiagnostico.psm1` | **Lógica pura** (vereditos, limites, achados, HTML, corpo da API). Sem I/O. 100% testável. |
| `Diagnostico-GLPI.ps1` | **Orquestrador** (I/O): API GLPI + coleta WinRM read-only + monta e posta o relatório. |
| `tests/GlpiDiagnostico.Tests.ps1` | Testes Pester 5 da lógica pura (31 testes). |

## Guard-rail (Fase 2a)

O `ScriptBlock` remoto contém **exclusivamente** comandos de leitura: `Get-*`, `Test-*`,
`Resolve-*`, `Measure-*`, `Get-CimInstance`, `Get-WinEvent`, `netsh ... show`. **Nenhum**
verbo mutante (`Set/Stop/Start/Restart/Clear/Remove/New/Disable/Enable/Repair`). Ações que
alteram a máquina são a Fase 2b (com confirmação + log).

> **Importante:** WinRM concede acesso **admin** no alvo. O caráter read-only é garantido
> pelo *conteúdo do script*, não pelo WinRM. Por isso a GPO deve **restringir a origem** do
> WinRM ao IP do DC (Scope > Remote IP na regra de firewall).

## Pré-requisitos

**No DC (onde o script roda):**
- Windows PowerShell 5.1, sessão **Domain Admin** (Kerberos → sem TrustedHosts).
- **WinRM habilitado nas estações via GPO** (ver plano de implementação, passo GPO). Sem
  isso, cada máquina cai no aviso "WinRM indisponível".
- Config do GLPI (URL + tokens) — ver abaixo.
- CA interna confiável (o DC do domínio já confia; a estação também). Se rodar de máquina
  fora do domínio, use `-SkipCertCheck`.

**No GLPI (já validado em 2026-07-01):**
- API REST habilitada e acessível pelo **caminho externo HTTPS** (via Caddy) — ✅ testado.
- Conta `ipe.ia`: perfil **Admin (id 3)**, direito `computer=127` (lê Computadores) — ✅.
- **Auto-hostname** depende do **inventário populado**. Hoje `search/Computer = 0` (frota
  ainda não inventariada). Até encher, use sempre `-Hostname`. Quando encher, confirme em
  qual **entidade** os PCs caem; a `ipe.ia` está na entidade 3 (TI) — se os PCs não ficarem
  sob a 3, dar à `ipe.ia` acesso em **entidade 0 recursivo**.

## Configuração

Crie `glpi-config.json` ao lado do script (ou use variáveis de ambiente
`GLPI_PUBLIC_URL` / `GLPI_APP_TOKEN` / `GLPI_USER_TOKEN`):

```json
{
  "Url": "https://glpi.ipeconect.com.br",
  "AppToken": "<app_token do cliente de API>",
  "UserToken": "<user_token da conta ipe.ia>"
}
```

> ⚠️ O arquivo contém **segredos**. Restrinja o ACL (só Administrators/SYSTEM):
> `icacls glpi-config.json /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F"` (SIDs =
> Administradores + SISTEMA; à prova de idioma — em Windows pt-BR os nomes "Administrators"/"SYSTEM" falham).
> Não versionar. Os tokens são os mesmos já em uso em `C:\glpi-ia\.env`.

## Uso

```powershell
# Com hostname explícito (recomendado hoje):
.\Diagnostico-GLPI.ps1 -TicketId 7490 -Hostname COMPUTADOR09

# Auto-resolução pelo solicitante do chamado (quando o inventário estiver cheio):
.\Diagnostico-GLPI.ps1 -TicketId 7490

# Teste sem postar (imprime o HTML no console):
.\Diagnostico-GLPI.ps1 -TicketId 7490 -Hostname COMPUTADOR09 -Preview

# Fora do domínio (CA não confiável na máquina):
.\Diagnostico-GLPI.ps1 -TicketId 7490 -Hostname COMPUTADOR09 -SkipCertCheck
```

Parâmetros de rede ajustáveis: `-InternalIp` (default `10.0.1.4`), `-InternalDnsName`,
`-ExternalDnsName`, `-InternetIp`, `-MailHost`/`-MailPort`.

## Testes

```powershell
Import-Module Pester -MinimumVersion 5.0.0 -Force
$cfg = New-PesterConfiguration
$cfg.Run.Path = '.\tests'
Invoke-Pester -Configuration $cfg   # 31 passed
```

## Status (2026-07-01)

- ✅ Módulo puro + 31 testes Pester passando.
- ✅ Orquestrador escrito; sintaxe validada; render do relatório validado com dados simulados.
- ✅ API GLPI validada (caminho externo, field IDs, extração do solicitante).
- ⏳ **Pendente (acabamento no DC):** GPO do WinRM; rodar contra 1 máquina real; teste do
  POST de acompanhamento ao vivo (evitado à noite para não disparar e-mail).
