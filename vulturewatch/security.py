"""Módulo de segurança e validação"""
import re
import html
from urllib.parse import urlparse
from pathlib import Path
from typing import Optional


def validate_slack_webhook_url(url: str) -> bool:
    """
    Valida URL de webhook do Slack
    
    Args:
        url: URL para validar
    
    Returns:
        True se válida, False caso contrário
    """
    if not url or not isinstance(url, str):
        return False
    
    # Slack webhooks devem começar com https://hooks.slack.com/services/
    if not url.startswith("https://hooks.slack.com/services/"):
        return False
    
    # Valida formato básico de URL
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False
        if parsed.netloc != "hooks.slack.com":
            return False
        if not parsed.path.startswith("/services/"):
            return False
        return True
    except Exception:
        return False


def validate_cve_id(cve_id: str) -> bool:
    """
    Valida formato de CVE ID
    
    Args:
        cve_id: CVE ID para validar (ex: CVE-2024-1234)
    
    Returns:
        True se válido, False caso contrário
    """
    if not cve_id or not isinstance(cve_id, str):
        return False
    
    # Formato: CVE-YYYY-NNNN ou CVE-YYYY-NNNNN
    pattern = r'^CVE-\d{4}-\d{4,7}$'
    return bool(re.match(pattern, cve_id.upper()))


def sanitize_html(text: str) -> str:
    """
    Escapa caracteres HTML para prevenir XSS
    
    Args:
        text: Texto para sanitizar
    
    Returns:
        Texto com HTML escapado
    """
    if not text:
        return ""
    
    # Escapa caracteres HTML especiais
    return html.escape(str(text), quote=True)


def sanitize_path(path: str, base_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Sanitiza e valida caminho de arquivo para prevenir path traversal
    
    Args:
        path: Caminho para sanitizar
        base_dir: Diretório base permitido (opcional)
    
    Returns:
        Path sanitizado ou None se inválido
    """
    if not path:
        return None
    
    try:
        # Converte para Path e resolve caminhos relativos
        resolved_path = Path(path).resolve()
        
        # Se base_dir especificado, verifica que está dentro
        if base_dir:
            base_dir_resolved = Path(base_dir).resolve()
            try:
                # Verifica que o caminho está dentro do base_dir
                resolved_path.relative_to(base_dir_resolved)
            except ValueError:
                # Path está fora do diretório base
                return None
        
        return resolved_path
    except Exception:
        return None


def validate_database_url(db_url: str) -> bool:
    """
    Valida URL de banco de dados
    
    Args:
        db_url: URL do banco de dados
    
    Returns:
        True se válida, False caso contrário
    """
    if not db_url or not isinstance(db_url, str):
        return False
    
    # SQLite: sqlite:///path
    if db_url.startswith("sqlite:///"):
        return True
    
    # PostgreSQL: postgresql://user:pass@host:port/db
    if db_url.startswith("postgresql://") or db_url.startswith("postgres://"):
        try:
            parsed = urlparse(db_url)
            # Verifica que não contém comandos SQL suspeitos
            suspicious = ["DROP", "DELETE", "TRUNCATE", "--", "/*", "*/"]
            db_url_upper = db_url.upper()
            if any(cmd in db_url_upper for cmd in suspicious):
                return False
            return True
        except Exception:
            return False
    
    return False

