FROM python:3.11-slim

WORKDIR /app

# Instala dependências do sistema
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copia arquivos de dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia código fonte
COPY . .

# Instala o pacote
RUN pip install -e .

# Cria diretório para SBOM e banco de dados
RUN mkdir -p /app/sbom /app/data

# Volume para persistência
VOLUME ["/app/data", "/app/sbom"]

# Comando padrão
CMD ["python", "-m", "vulturewatch.main"]

