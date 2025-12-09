"""Notificador Slack"""
import json
import requests
from typing import Dict
import logging
from ..security import validate_slack_webhook_url

logger = logging.getLogger(__name__)


class SlackNotifier:
    """Envia notificações para Slack"""
    
    def __init__(self, webhook_url: str, channel: str = "#security-alerts"):
        # Valida URL do webhook
        if not validate_slack_webhook_url(webhook_url):
            raise ValueError(f"URL de webhook do Slack inválida: {webhook_url}")
        
        self.webhook_url = webhook_url
        self.channel = channel
    
    def send_alert(self, cve: Dict) -> bool:
        """
        Envia alerta de CVE para Slack
        
        Args:
            cve: Dicionário com informações do CVE
        
        Returns:
            True se enviado com sucesso
        """
        try:
            message = self._format_message(cve)
            
            payload = {
                "channel": self.channel,
                "text": f":rotating_light: [CRITICAL CVE] {cve.get('cve_id')}",
                "blocks": message["blocks"],
                "unfurl_links": True,
                "unfurl_media": True
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Alerta enviado para Slack: {cve.get('cve_id')}")
            return True
        
        except Exception as e:
            logger.error(f"Erro ao enviar alerta para Slack: {e}")
            return False
    
    def _format_message(self, cve: Dict) -> Dict:
        """Formata mensagem do Slack com blocos ricos"""
        cve_id = cve.get("cve_id", "N/A")
        components = cve.get("components", [])
        component_name = components[0].get("name", "N/A") if components else "N/A"
        version_range = components[0].get("version_range", "") if components else ""
        
        cvss_score = cve.get("cvss_score", 0.0)
        severity = cve.get("severity", "UNKNOWN")
        
        # Determina categoria e maturidade
        is_kev = cve.get("is_kev", False)
        has_exploit = cve.get("has_public_exploit", False)
        has_poc = cve.get("has_public_poc", False)
        maturity = cve.get("max_maturity_level", 0)
        
        maturity_text = []
        if is_kev:
            maturity_text.append("KEV")
        if has_exploit:
            maturity_text.append("Exploit público")
        if has_poc:
            maturity_text.append("PoC pública")
        maturity_text_str = " + ".join(maturity_text) if maturity_text else "N/A"
        
        # Links
        nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        exploit_links = cve.get("exploit_links", [])
        
        # Onde o componente é usado
        used_in = cve.get("used_in", "")
        used_in_text = f"*Usado em:* {used_in}\n" if used_in else ""
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f":rotating_light: [CRITICAL CVE] Exploit público/KEV detectado"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*CVE:*\n{cve_id}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Componente:*\n{component_name}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Versões afetadas:*\n{version_range or 'N/A'}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*CVSS v3:*\n{cvss_score} ({severity})"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Categoria:*\n{cve.get('description', 'N/A')[:100]}..."
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Maturidade:*\n{maturity_text_str}"
                    }
                ]
            }
        ]
        
        # Seção de "Por que importa"
        if used_in:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Por que você deve ligar pra isso?*\n\nO componente foi identificado no seu SBOM/projeto:\n• Componente: {component_name}\n{used_in_text}"
                }
            })
        
        # Seção de fontes
        sources_text = f"• NVD: {nvd_link}\n"
        if is_kev:
            sources_text += "• KEV: https://www.cisa.gov/known-exploited-vulnerabilities\n"
        
        if exploit_links:
            for link in exploit_links[:3]:  # Limita a 3 links
                sources_text += f"• {link.get('source', 'Exploit')}: {link.get('url', '')}\n"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Fontes:*\n{sources_text}"
            }
        })
        
        # Próximos passos
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Próximos passos sugeridos:*\n1. Verificar se a versão em produção está dentro do range afetado\n2. Planejar upgrade para versão corrigida\n3. Avaliar logs de possível exploração"
            }
        })
        
        return {"blocks": blocks}

