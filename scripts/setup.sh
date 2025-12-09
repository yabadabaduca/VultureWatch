#!/bin/bash
# Script de setup inicial do VultureWatch

set -e

echo "🦅 Configurando VultureWatch..."

# Verifica Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 não encontrado. Por favor, instale Python 3.8 ou superior."
    exit 1
fi

echo "✅ Python encontrado: $(python3 --version)"

# Cria ambiente virtual (opcional)
if [ ! -d "venv" ]; then
    echo "📦 Criando ambiente virtual..."
    python3 -m venv venv
fi

# Ativa ambiente virtual
echo "🔌 Ativando ambiente virtual..."
source venv/bin/activate

# Instala dependências
echo "📥 Instalando dependências..."
pip install --upgrade pip
pip install -r requirements.txt

# Instala pacote
echo "📦 Instalando VultureWatch..."
pip install -e .

# Cria diretórios necessários
echo "📁 Criando diretórios..."
mkdir -p sbom data

# Copia arquivos de exemplo
if [ ! -f "config.yaml" ]; then
    echo "⚙️  Criando config.yaml..."
    cp config.yaml.example config.yaml
    echo "⚠️  Por favor, edite config.yaml com suas configurações!"
fi

if [ ! -f ".env" ]; then
    echo "🔐 Criando .env..."
    cp env.example .env
    echo "⚠️  Por favor, edite .env com suas credenciais!"
fi

# Gera SBOM de exemplo
if [ ! -f "sbom/example-sbom.json" ]; then
    echo "📋 Gerando SBOM de exemplo..."
    python3 scripts/generate_example_sbom.py
fi

echo ""
echo "✅ Setup concluído!"
echo ""
echo "Próximos passos:"
echo "1. Edite config.yaml com suas configurações"
echo "2. Edite .env com suas credenciais (Slack/Telegram)"
echo "3. Configure seu SBOM em ./sbom/"
echo "4. Execute: python -m vulturewatch.main"
echo ""

