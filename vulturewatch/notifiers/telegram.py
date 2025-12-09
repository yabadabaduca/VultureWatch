"""Notificador Telegram"""
from telegram import Bot
from telegram.error import TelegramError
from typing import Dict
import logging
from ..security import sanitize_html, validate_cve_id

logger = logging.getLogger(__name__)


class TelegramNotifier:
    """Envia notificações para Telegram"""
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.bot = Bot(token=bot_token)
    
    def send_alert(self, cve: Dict) -> bool:
        """
        Envia alerta de CVE para Telegram
        
        Args:
            cve: Dicionário com informações do CVE
        
        Returns:
            True se enviado com sucesso
        """
        try:
            message = self._format_message(cve)
            
            self.bot.send_message(
                chat_id=self.chat_id,
                text=message,
                parse_mode="HTML",
                disable_web_page_preview=False
            )
            
            logger.info(f"Alerta enviado para Telegram: {cve.get('cve_id')}")
            return True
        
        except TelegramError as e:
            logger.error(f"Erro ao enviar alerta para Telegram: {e}")
            return False
    
    def _format_message(self, cve: Dict) -> str:
        """Formata mensagem do Telegram"""
        cve_id = cve.get("cve_id", "N/A")
        components = cve.get("components", [])
        component_name = components[0].get("name", "N/A") if components else "N/A"
        
        # Sanitiza entrada para prevenir XSS
        cve_id_safe = sanitize_html(cve_id)
        component_name_safe = sanitize_html(component_name)
        
        cvss_score = cve.get("cvss_score", 0.0)
        
        # Determina maturidade
        is_kev = cve.get("is_kev", False)
        has_exploit = cve.get("has_public_exploit", False)
        has_poc = cve.get("has_public_poc", False)
        
        maturity_text = []
        if is_kev:
            maturity_text.append("KEV")
        if has_exploit:
            maturity_text.append("Exploit público")
        if has_poc:
            maturity_text.append("PoC")
        maturity_text_str = " + ".join(maturity_text) if maturity_text else "N/A"
        
        # Links - valida CVE ID antes de usar na URL
        if validate_cve_id(cve_id):
            nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id_safe}"
        else:
            nvd_link = "https://nvd.nist.gov"
        
        exploit_links = cve.get("exploit_links", [])
        
        # Onde o componente é usado
        used_in = cve.get("used_in", "")
        used_in_safe = sanitize_html(used_in) if used_in else ""
        used_in_text = f"\n\nUsado em: {used_in_safe}" if used_in_safe else ""
        
        # Monta mensagem com HTML escapado
        message = f"""🚨 <b>[CVE CRÍTICA] Exploit/KEV detectado</b>

<b>CVE:</b> {cve_id_safe}
<b>Componente:</b> {component_name_safe}
<b>CVSS:</b> {cvss_score}
<b>Maturidade:</b> {maturity_text_str}{used_in_text}

<b>Saiba mais:</b> <a href="{nvd_link}">NVD</a>"""
        
        # Adiciona links de exploits (URLs já são confiáveis, mas sanitiza texto)
        if exploit_links:
            for link in exploit_links[:2]:  # Limita a 2 links
                source_name = sanitize_html(link.get("source", "Exploit").replace("_", " ").title())
                url = link.get("url", "")
                # Valida que URL é HTTPS antes de incluir
                if url.startswith("https://"):
                    message += f" | <a href=\"{url}\">{source_name}</a>"
        
        return message

