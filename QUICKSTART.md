# 🚀 Guia Rápido de Início

## Instalação Rápida

### Opção 1: Script Automático

```bash
./scripts/setup.sh
```

### Opção 2: Manual

```bash
# 1. Instalar dependências
pip install -r requirements.txt
pip install -e .

# 2. Configurar
cp config.yaml.example config.yaml
cp env.example .env

# 3. Editar configurações
nano config.yaml  # Configure Slack/Telegram
nano .env         # Configure credenciais

# 4. Gerar SBOM de exemplo (opcional)
python scripts/generate_example_sbom.py
```

## Configuração Mínima

### 1. Slack (Escolha um)

**Opção A: Webhook (Mais simples)**
1. Acesse: https://api.slack.com/apps
2. Crie um app → Incoming Webhooks → Ative
3. Copie a URL do webhook
4. Adicione em `config.yaml`:
```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    channel: "#security-alerts"
```

### 2. Telegram (Escolha um)

1. Fale com [@BotFather](https://t.me/botfather)
2. `/newbot` → Escolha nome → Copie token
3. Adicione bot ao grupo/canal
4. Obtenha chat_id:
   - Para grupos: use [@getidsbot](https://t.me/getidsbot)
   - Ou envie mensagem e use: `https://api.telegram.org/bot<TOKEN>/getUpdates`
5. Configure em `config.yaml`:
```yaml
notifications:
  telegram:
    enabled: true
    bot_token: "123456:ABC-DEF..."
    chat_id: "-1001234567890"
```

### 3. SBOM (Opcional mas recomendado)

```bash
# Python
pip install cyclonedx-bom
cyclonedx-py -o sbom/sbom.json

# Node.js
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm -o sbom/sbom.json

# Ou use o exemplo
python scripts/generate_example_sbom.py
```

## Executar

### Modo Scheduler (contínuo)
```bash
python -m vulturewatch.main
```

### Modo uma execução
```bash
RUN_ONCE=true python -m vulturewatch.main
```

### Com Docker
```bash
docker-compose up -d
```

## Verificar Funcionamento

1. Verifique logs:
```bash
# Se rodando diretamente, verá logs no console
# Com Docker:
docker-compose logs -f vulturewatch
```

2. Verifique banco de dados:
```bash
sqlite3 vulturewatch.db "SELECT * FROM alerts_sent;"
```

3. Teste manualmente:
```bash
# Execute uma vez e verifique se recebe notificações
RUN_ONCE=true python -m vulturewatch.main
```

## Troubleshooting

### Erro: "Arquivo de configuração não encontrado"
```bash
cp config.yaml.example config.yaml
```

### Erro: "Slack webhook_url não configurado"
- Verifique se `webhook_url` está preenchido em `config.yaml`
- Ou configure via variável de ambiente: `export SLACK_WEBHOOK_URL=...`

### Erro: "Telegram bot_token não configurado"
- Verifique se `bot_token` e `chat_id` estão preenchidos
- Certifique-se de que o bot foi adicionado ao grupo/canal

### Nenhuma notificação recebida
- Verifique se há CVEs críticas recentes (pode não haver)
- Verifique logs para erros
- Teste com `maturity_min_level: 1` temporariamente
- Verifique se componentes do SBOM estão sendo detectados

### Rate limit do NVD
- Obtenha API key gratuita em: https://nvd.nist.gov/developers/request-an-api-key
- Configure em `config.yaml` ou `.env`:
```yaml
sources:
  nvd:
    api_key: "sua-api-key"
```

## Próximos Passos

1. ✅ Configure notificações (Slack ou Telegram)
2. ✅ Configure SBOM com seus componentes reais
3. ✅ Ajuste `maturity_min_level` conforme necessário
4. ✅ Configure `poll_interval` (ex: "6h" para verificar a cada 6 horas)
5. ✅ Configure deploy em produção (Docker, Kubernetes, etc.)

## Exemplo de Deploy em Produção

### Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vulturewatch
spec:
  schedule: "0 */6 * * *"  # A cada 6 horas
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: vulturewatch
            image: seu-registry/vulturewatch:latest
            env:
            - name: RUN_ONCE
              value: "true"
            - name: SLACK_WEBHOOK_URL
              valueFrom:
                secretKeyRef:
                  name: vulturewatch-secrets
                  key: slack-webhook-url
            volumeMounts:
            - name: config
              mountPath: /app/config.yaml
              subPath: config.yaml
            - name: sbom
              mountPath: /app/sbom
          volumes:
          - name: config
            configMap:
              name: vulturewatch-config
          - name: sbom
            configMap:
              name: vulturewatch-sbom
          restartPolicy: OnFailure
```

### GitHub Actions

```yaml
name: VultureWatch
on:
  schedule:
    - cron: '0 */6 * * *'  # A cada 6 horas
  workflow_dispatch:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pip install -e .
      - run: python -m vulturewatch.main
        env:
          RUN_ONCE: "true"
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
          TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}
          TELEGRAM_CHAT_ID: ${{ secrets.TELEGRAM_CHAT_ID }}
```

