"""Módulo de configuração"""
import os
import yaml
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Carrega variáveis de ambiente
load_dotenv()


class Config:
    """Gerencia configurações do VultureWatch"""
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = os.getenv("CONFIG_PATH", "config.yaml")
        
        self.config_path = Path(config_path)
        self._config = self._load_config()
        self._load_env_overrides()
    
    def _load_config(self) -> dict:
        """Carrega configuração do arquivo YAML"""
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Arquivo de configuração não encontrado: {self.config_path}\n"
                "Copie config.yaml.example para config.yaml e configure."
            )
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def _load_env_overrides(self):
        """Sobrescreve configurações com variáveis de ambiente"""
        # Mapeamento de variáveis de ambiente para caminhos de configuração
        env_mappings = [
            ("SLACK_WEBHOOK_URL", ["notifications", "slack", "webhook_url"]),
            ("SLACK_CHANNEL", ["notifications", "slack", "channel"]),
            ("TELEGRAM_BOT_TOKEN", ["notifications", "telegram", "bot_token"]),
            ("TELEGRAM_CHAT_ID", ["notifications", "telegram", "chat_id"]),
            ("NVD_API_KEY", ["sources", "nvd", "api_key"]),
        ]
        
        for env_var, config_path in env_mappings:
            value = os.getenv(env_var)
            if value:
                self._set_nested_config(config_path, value)
    
    def _set_nested_config(self, path: list, value: str):
        """Define valor em caminho aninhado do config"""
        config = self._config
        for key in path[:-1]:
            config = config.setdefault(key, {})
        config[path[-1]] = value
    
    @property
    def poll_interval(self) -> str:
        return self._config.get("poll_interval", "1h")
    
    @property
    def cvss_min_score(self) -> float:
        return self._config.get("cvss_min_score", 9.0)
    
    @property
    def maturity_min_level(self) -> int:
        return self._config.get("maturity_min_level", 2)
    
    @property
    def filters(self) -> dict:
        return self._config.get("filters", {})
    
    @property
    def notifications(self) -> dict:
        return self._config.get("notifications", {})
    
    @property
    def sources(self) -> dict:
        return self._config.get("sources", {})
    
    @property
    def sbom(self) -> dict:
        return self._config.get("sbom", {})
    
    @property
    def database(self) -> dict:
        return self._config.get("database", {})

