# 📋 Exemplos de Configuração

## Configuração Básica (Desenvolvimento)

```yaml
poll_interval: "1h"
cvss_min_score: 9.0
maturity_min_level: 2

filters:
  only_components_in_sbom: false  # Alerta sobre tudo inicialmente
  include_kev_even_if_cvss_below_min: true

notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    channel: "#security-alerts"
  
  telegram:
    enabled: false

sources:
  nvd:
    enabled: true
    api_key: ""
  
  kev:
    enabled: true
  
  exploit_db:
    enabled: true
  
  metasploit:
    enabled: true

sbom:
  enabled: false  # Desabilitado para testes

database:
  type: "sqlite"
  path: "./vulturewatch.db"
```

## Configuração Produção (Restritiva)

```yaml
poll_interval: "6h"  # Verifica a cada 6 horas
cvss_min_score: 9.0
maturity_min_level: 2  # Apenas PoCs funcionais ou exploits

filters:
  only_components_in_sbom: true  # Apenas componentes usados
  include_kev_even_if_cvss_below_min: true

notifications:
  slack:
    enabled: true
    webhook_url: "${SLACK_WEBHOOK_URL}"  # Via env var
    channel: "#security-critical"
  
  telegram:
    enabled: true
    bot_token: "${TELEGRAM_BOT_TOKEN}"
    chat_id: "${TELEGRAM_CHAT_ID}"

sources:
  nvd:
    enabled: true
    api_key: "${NVD_API_KEY}"  # Recomendado para produção
  
  kev:
    enabled: true
  
  exploit_db:
    enabled: true
  
  metasploit:
    enabled: true

sbom:
  enabled: true
  path: "/app/sbom"
  format: "cyclonedx-json"

database:
  type: "postgresql"
  url: "${DATABASE_URL}"
```

## Configuração Alta Sensibilidade

```yaml
poll_interval: "30m"  # Verifica a cada 30 minutos
cvss_min_score: 7.0  # CVSS mais baixo
maturity_min_level: 1  # Inclui PoCs teóricas também

filters:
  only_components_in_sbom: true
  include_kev_even_if_cvss_below_min: true

notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    channel: "#security-alerts"
  
  telegram:
    enabled: true
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"

sources:
  nvd:
    enabled: true
    api_key: "YOUR_NVD_API_KEY"
  
  kev:
    enabled: true
  
  exploit_db:
    enabled: true
  
  github:
    enabled: true

sbom:
  enabled: true
  path: "./sbom"
  format: "cyclonedx-json"

database:
  type: "sqlite"
  path: "./vulturewatch.db"
```

## Configuração Apenas KEV

```yaml
poll_interval: "24h"
cvss_min_score: 10.0  # Muito alto (só KEV vai passar)
maturity_min_level: 0  # Não importa, só KEV

filters:
  only_components_in_sbom: true
  include_kev_even_if_cvss_below_min: true  # Importante!

notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    channel: "#kev-alerts"
  
  telegram:
    enabled: false

sources:
  nvd:
    enabled: true
  
  kev:
    enabled: true
  
  exploit_db:
    enabled: false  # Não precisa
  
  github:
    enabled: false

sbom:
  enabled: true
  path: "./sbom"
  format: "cyclonedx-json"

database:
  type: "sqlite"
  path: "./vulturewatch.db"
```

## Configuração Docker Compose

Para usar com Docker Compose, mantenha configurações sensíveis em `.env`:

```yaml
# config.yaml
poll_interval: "6h"
cvss_min_score: 9.0
maturity_min_level: 2

filters:
  only_components_in_sbom: true
  include_kev_even_if_cvss_below_min: true

notifications:
  slack:
    enabled: true
    webhook_url: ""  # Será sobrescrito por env var
    channel: "#security-alerts"
  
  telegram:
    enabled: true
    bot_token: ""
    chat_id: ""

sources:
  nvd:
    enabled: true
    api_key: ""

sbom:
  enabled: true
  path: "/app/sbom"
  format: "cyclonedx-json"

database:
  type: "sqlite"
  path: "/app/data/vulturewatch.db"
```

E no `.env`:
```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
TELEGRAM_CHAT_ID=-1001234567890
NVD_API_KEY=your-nvd-api-key
```

## Configuração Kubernetes

Para Kubernetes, use ConfigMaps e Secrets:

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vulturewatch-config
data:
  config.yaml: |
    poll_interval: "6h"
    cvss_min_score: 9.0
    maturity_min_level: 2
    filters:
      only_components_in_sbom: true
      include_kev_even_if_cvss_below_min: true
    notifications:
      slack:
        enabled: true
        channel: "#security-alerts"
      telegram:
        enabled: true
    sources:
      nvd:
        enabled: true
      kev:
        enabled: true
    sbom:
      enabled: true
      path: "/app/sbom"
      format: "cyclonedx-json"
    database:
      type: "sqlite"
      path: "/app/data/vulturewatch.db"
```

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: vulturewatch-secrets
type: Opaque
stringData:
  slack-webhook-url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  telegram-bot-token: "123456:ABC-DEF..."
  telegram-chat-id: "-1001234567890"
  nvd-api-key: "your-nvd-api-key"
```

## Dicas de Configuração

### Intervalos Recomendados

- **Desenvolvimento/Testes**: `"5m"` ou `"15m"`
- **Produção Normal**: `"6h"` ou `"12h"`
- **Alta Segurança**: `"1h"` ou `"3h"`
- **Baixa Prioridade**: `"24h"` ou `"48h"`

### Níveis de Maturidade

- **0**: Apenas artigos/whitepapers (muito ruído)
- **1**: PoCs teóricas (pode ter ruído)
- **2**: PoCs funcionais (recomendado)
- **3**: Apenas exploits maduros (pode perder PoCs importantes)

### CVSS Scores

- **10.0**: Apenas críticas absolutas
- **9.0**: Críticas (recomendado)
- **7.0**: Críticas e altas (mais alertas)
- **5.0**: Médias e acima (muito ruído)

### Filtros SBOM

- `only_components_in_sbom: false`: Alerta sobre tudo (útil para descobrir componentes)
- `only_components_in_sbom: true`: Apenas componentes usados (recomendado para produção)

