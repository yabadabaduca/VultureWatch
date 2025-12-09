# VultureWatch 🦅

Ferramenta de monitoramento de CVEs críticas com exploits públicos, PoCs e vulnerabilidades da lista KEV (Known Exploited Vulnerabilities) da CISA.

## 🎯 Objetivo

O VultureWatch monitora continuamente vulnerabilidades críticas (CVSS ≥ 9) que possuem:
- Exploit público (Exploit-DB, Metasploit, etc.)
- PoC pública com maturidade razoável
- Presença na lista KEV da CISA

E notifica apenas sobre componentes que você realmente usa (via SBOM/SCA).

## ✨ Funcionalidades

- 🔍 **Coleta automática** de CVEs do NVD (National Vulnerability Database)
- 🎯 **Filtragem inteligente** por CVSS, maturidade de exploit e lista KEV
- 📦 **Integração com SBOM** (CycloneDX e SPDX) para filtrar apenas componentes usados
- 🔔 **Notificações** via Slack e Telegram com contexto útil
- 💾 **Controle de estado** para evitar spam de alertas duplicados
- ⏰ **Scheduler configurável** (cron-like) para execução periódica
- 📊 **Sistema de maturidade** de exploits (0-3) para reduzir ruído

## 🚀 Instalação

### Pré-requisitos

- Python 3.8 ou superior
- pip

### Instalação

1. Clone o repositório:
```bash
git clone <repo-url>
cd VultureWatch
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

Ou instale como pacote:
```bash
pip install -e .
```

## ⚙️ Configuração

### 1. Arquivo de configuração

Copie o arquivo de exemplo e configure:
```bash
cp config.yaml.example config.yaml
```

Edite `config.yaml` com suas preferências:

```yaml
poll_interval: "1h"  # Intervalo de verificação
cvss_min_score: 9.0  # Score CVSS mínimo
maturity_min_level: 2  # Nível mínimo de maturidade (0-3)

filters:
  only_components_in_sbom: true  # Filtrar apenas componentes no SBOM
  include_kev_even_if_cvss_below_min: true  # Incluir KEV mesmo com CVSS menor

notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    channel: "#security-alerts"
  
  telegram:
    enabled: true
    bot_token: "123456:ABC-DEF..."
    chat_id: "-1001234567890"
```

### 2. Variáveis de ambiente (opcional)

Você também pode usar variáveis de ambiente. Copie o exemplo:
```bash
cp env.example .env
```

E preencha os valores no `.env`:
- `SLACK_WEBHOOK_URL`: Webhook do Slack
- `TELEGRAM_BOT_TOKEN`: Token do bot do Telegram
- `TELEGRAM_CHAT_ID`: ID do chat/grupo do Telegram
- `NVD_API_KEY`: (Opcional) API key do NVD para rate limit maior

### 3. Configurar Slack

1. Acesse https://api.slack.com/apps
2. Crie um novo app ou use um existente
3. Vá em "Incoming Webhooks"
4. Ative e crie um webhook
5. Copie a URL do webhook para `config.yaml`

### 4. Configurar Telegram

1. Fale com [@BotFather](https://t.me/botfather) no Telegram
2. Use `/newbot` para criar um bot
3. Copie o token fornecido
4. Adicione o bot ao grupo/canal desejado
5. Obtenha o `chat_id`:
   - Para grupos: use [@userinfobot](https://t.me/userinfobot) ou APIs
   - Para canais: use `@getidsbot` ou APIs
6. Configure no `config.yaml`

### 5. Configurar SBOM (opcional mas recomendado)

O VultureWatch pode filtrar apenas componentes que você realmente usa através de arquivos SBOM.

#### Gerar SBOM com CycloneDX

Para projetos Python:
```bash
pip install cyclonedx-bom
cyclonedx-py -o sbom.json
```

Para projetos Node.js:
```bash
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm -o sbom.json
```

Para projetos Java/Maven:
```bash
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
```

Coloque o arquivo SBOM em `./sbom/` ou configure o caminho em `config.yaml`.

## 📖 Uso

### Modo Scheduler (recomendado)

Executa verificações periódicas conforme configurado:
```bash
python -m vulturewatch.main
```

Ou usando o comando instalado:
```bash
vulturewatch
```

### Modo uma execução

Para executar apenas uma vez:
```bash
RUN_ONCE=true python -m vulturewatch.main
```

### Usando Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

CMD ["python", "-m", "vulturewatch.main"]
```

### Usando Kubernetes CronJob

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
            image: vulturewatch:latest
            env:
            - name: RUN_ONCE
              value: "true"
            volumeMounts:
            - name: config
              mountPath: /app/config.yaml
              subPath: config.yaml
          volumes:
          - name: config
            configMap:
              name: vulturewatch-config
          restartPolicy: OnFailure
```

## 🏗️ Arquitetura

```
VultureWatch
├── collectors/          # Coletores de vulnerabilidades
│   ├── nvd.py          # NVD (National Vulnerability Database)
│   ├── kev.py          # Lista KEV da CISA
│   ├── exploit_db.py   # Exploit-DB
│   └── github.py       # GitHub (PoCs)
├── filter.py           # Filtragem e enriquecimento
├── sbom_parser.py      # Parser de SBOM
├── notifiers/          # Notificadores
│   ├── slack.py
│   └── telegram.py
├── database.py         # Controle de estado
├── config.py           # Configuração
└── main.py             # Loop principal
```

## 🔧 Sistema de Maturidade

O VultureWatch avalia a maturidade de exploits/PoCs em uma escala de 0-3:

- **0**: Apenas artigo/whitepaper teórico
- **1**: PoC teórica sem steps claros
- **2**: PoC funcional com instruções de execução
- **3**: Exploit integrado (script pronto, módulo Metasploit, etc.)

Configure `maturity_min_level` em `config.yaml` para filtrar por maturidade.

## 📊 Exemplo de Notificação

### Slack

```
🚨 [CRITICAL CVE] Exploit público/KEV detectado

CVE: CVE-2025-XXXX
Componente: log4j-core
Versões afetadas: <= 2.17.0
CVSS v3: 9.8 (Critical)
Maturidade: Exploit público + KEV

Por que você deve ligar pra isso?
O componente foi identificado no seu SBOM/projeto:
• Componente: log4j-core
• Usado em: pagamento-api

Fontes:
• NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-XXXX
• KEV: https://www.cisa.gov/known-exploited-vulnerabilities
• Exploit PoC: https://www.exploit-db.com/exploits/XXXXX

Próximos passos sugeridos:
1. Verificar se a versão em produção está dentro do range afetado
2. Planejar upgrade para versão corrigida: 2.17.1+
3. Avaliar logs de possível exploração
```

### Telegram

```
🚨 [CVE CRÍTICA] Exploit/KEV detectado

CVE: CVE-2025-XXXX
Componente: log4j-core
CVSS: 9.8
Maturidade: Exploit público + KEV

Usado em: pagamento-api

Saiba mais: NVD | Exploit-DB
```

## 🗄️ Banco de Dados

Por padrão, o VultureWatch usa SQLite para controlar alertas já enviados. Você pode configurar PostgreSQL em `config.yaml`:

```yaml
database:
  type: "postgresql"
  url: "postgresql://user:pass@localhost/vulturewatch"
```

## 🧪 Desenvolvimento

### Estrutura do projeto

```
VultureWatch/
├── vulturewatch/       # Código fonte
├── config.yaml.example # Exemplo de configuração
├── requirements.txt    # Dependências Python
├── setup.py           # Setup do pacote
└── README.md          # Este arquivo
```

### Executar testes

```bash
# Instalar em modo desenvolvimento
pip install -e .

# Executar
python -m vulturewatch.main
```

## 📝 Licença

MIT License

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor, abra uma issue ou pull request.

## ⚠️ Avisos

- Esta ferramenta é para fins educacionais e de segurança defensiva
- Sempre valide informações antes de tomar ações
- Use com responsabilidade e ética
- Não use para atividades maliciosas

## 📞 Suporte

Para questões e problemas, abra uma issue no repositório.
