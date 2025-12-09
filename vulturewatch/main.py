"""Main loop do VultureWatch"""
import logging
import schedule
import time
from datetime import datetime
from typing import List, Dict

from .config import Config
from .database import Database
from .collectors.nvd import NVDCollector
from .filter import CVEFilter
from .sbom_parser import SBOMParser
from .notifiers.slack import SlackNotifier
from .notifiers.telegram import TelegramNotifier

# Configura logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VultureWatch:
    """Classe principal do VultureWatch"""
    
    def __init__(self, config_path: str = None):
        self.config = Config(config_path)
        self.db = Database(self.config.database)
        
        # Inicializa parser de SBOM se configurado
        self.sbom_parser = None
        if self.config.sbom.get("enabled", False):
            sbom_path = self.config.sbom.get("path", "./sbom")
            sbom_format = self.config.sbom.get("format", "cyclonedx-json")
            # Define diretório base para prevenir path traversal
            from pathlib import Path
            base_dir = Path(sbom_path).parent.resolve() if Path(sbom_path).is_absolute() else Path(".").resolve()
            self.sbom_parser = SBOMParser(sbom_path, sbom_format, base_dir=base_dir)
        
        # Inicializa filtro
        filter_config = {
            "cvss_min_score": self.config.cvss_min_score,
            "maturity_min_level": self.config.maturity_min_level,
            "filters": self.config.filters
        }
        self.cve_filter = CVEFilter(filter_config, self.sbom_parser)
        
        # Inicializa coletores
        nvd_config = self.config.sources.get("nvd", {})
        self.nvd_collector = NVDCollector(nvd_config.get("api_key"))
        
        # Inicializa notificadores
        self.notifiers = []
        self._init_notifiers()
    
    def _init_notifiers(self):
        """Inicializa notificadores configurados"""
        # Slack
        slack_config = self.config.notifications.get("slack", {})
        if slack_config.get("enabled", False):
            webhook_url = slack_config.get("webhook_url")
            channel = slack_config.get("channel", "#security-alerts")
            if webhook_url:
                self.notifiers.append(SlackNotifier(webhook_url, channel))
            else:
                logger.warning("Slack habilitado mas webhook_url não configurado")
        
        # Telegram
        telegram_config = self.config.notifications.get("telegram", {})
        if telegram_config.get("enabled", False):
            bot_token = telegram_config.get("bot_token")
            chat_id = telegram_config.get("chat_id")
            if bot_token and chat_id:
                self.notifiers.append(TelegramNotifier(bot_token, chat_id))
            else:
                logger.warning("Telegram habilitado mas bot_token ou chat_id não configurados")
    
    def run_once(self):
        """Executa uma verificação única"""
        logger.info("Iniciando verificação de CVEs...")
        
        try:
            # Coleta CVEs recentes do NVD
            cves = self.nvd_collector.fetch_recent_cves(hours=24, cvss_min=self.config.cvss_min_score)
            
            if not cves:
                logger.info("Nenhuma CVE encontrada")
                return
            
            # Filtra CVEs críticas
            critical_cves = self.cve_filter.filter_critical_cves(cves)
            
            if not critical_cves:
                logger.info("Nenhuma CVE crítica encontrada após filtragem")
                return
            
            # Processa cada CVE
            for cve in critical_cves:
                self._process_cve(cve)
            
            logger.info(f"Verificação concluída. {len(critical_cves)} CVEs processadas")
        
        except Exception as e:
            logger.error(f"Erro durante verificação: {e}", exc_info=True)
    
    def _process_cve(self, cve: Dict):
        """Processa uma CVE e envia notificações se necessário"""
        cve_id = cve.get("cve_id")
        components = cve.get("components", [])
        
        if not components:
            logger.warning(f"CVE {cve_id} sem componentes, pulando")
            return
        
        # Processa cada componente afetado
        for component in components:
            component_name = component.get("name", "")
            
            if not component_name:
                continue
            
            # Verifica se já foi notificado
            if self.db.alert_already_sent(cve_id, component_name):
                logger.debug(f"Alerta já enviado para {cve_id} - {component_name}")
                continue
            
            # Envia notificações
            channels_notified = []
            for notifier in self.notifiers:
                try:
                    if notifier.send_alert(cve):
                        # Identifica canal pelo nome da classe
                        channel_name = type(notifier).__name__.lower().replace("notifier", "")
                        channels_notified.append(channel_name)
                except Exception as e:
                    logger.error(f"Erro ao enviar notificação: {e}")
            
            # Marca como enviado no banco
            if channels_notified:
                version_range = component.get("version_range", "")
                metadata = {
                    "cvss_score": cve.get("cvss_score"),
                    "is_kev": cve.get("is_kev", False),
                    "has_exploit": cve.get("has_public_exploit", False)
                }
                self.db.mark_alert_sent(
                    cve_id=cve_id,
                    component=component_name,
                    version_range=version_range,
                    channels=channels_notified,
                    metadata=metadata
                )
                logger.info(f"Alerta enviado para {cve_id} - {component_name} via {', '.join(channels_notified)}")
    
    def start_scheduler(self):
        """Inicia o scheduler"""
        poll_interval = self.config.poll_interval
        
        # Converte intervalo para formato do schedule
        if poll_interval.endswith("m"):
            minutes = int(poll_interval[:-1])
            schedule.every(minutes).minutes.do(self.run_once)
        elif poll_interval.endswith("h"):
            hours = int(poll_interval[:-1])
            schedule.every(hours).hours.do(self.run_once)
        elif poll_interval.endswith("d"):
            days = int(poll_interval[:-1])
            schedule.every(days).days.do(self.run_once)
        else:
            logger.error(f"Formato de intervalo inválido: {poll_interval}")
            return
        
        logger.info(f"Scheduler iniciado. Verificações a cada {poll_interval}")
        
        # Executa uma vez imediatamente
        self.run_once()
        
        # Loop principal
        while True:
            schedule.run_pending()
            time.sleep(60)  # Verifica a cada minuto


def main():
    """Função principal"""
    import sys
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    
    vulturewatch = VultureWatch(config_path)
    
    # Verifica se deve rodar uma vez ou em modo scheduler
    import os
    if os.getenv("RUN_ONCE", "false").lower() == "true":
        vulturewatch.run_once()
    else:
        vulturewatch.start_scheduler()


if __name__ == "__main__":
    main()

