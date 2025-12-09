"""Coletor da lista KEV (Known Exploited Vulnerabilities) da CISA"""
import requests
from typing import List, Dict
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class KEVCollector:
    """Coleta vulnerabilidades da lista KEV da CISA"""
    
    DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def __init__(self, url: str = None):
        self.url = url or self.DEFAULT_URL
        self.session = requests.Session()
    
    def fetch_kev_list(self) -> List[Dict]:
        """
        Busca lista completa de KEV
        
        Returns:
            Lista de CVEs na lista KEV
        """
        try:
            response = self.session.get(self.url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            kev_cves = []
            for vuln in vulnerabilities:
                kev_cves.append({
                    "cve_id": vuln.get("cveID"),
                    "vendor_project": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "vulnerability_name": vuln.get("vulnerabilityName", ""),
                    "date_added": vuln.get("dateAdded", ""),
                    "short_description": vuln.get("shortDescription", ""),
                    "required_action": vuln.get("requiredAction", ""),
                    "due_date": vuln.get("dueDate", ""),
                    "known_ransomware_campaign_use": vuln.get("knownRansomwareCampaignUse", ""),
                    "notes": vuln.get("notes", ""),
                    "source": "kev"
                })
            
            logger.info(f"Coletadas {len(kev_cves)} CVEs da lista KEV")
            return kev_cves
        
        except requests.RequestException as e:
            logger.error(f"Erro ao buscar lista KEV: {e}")
            return []
    
    def is_kev(self, cve_id: str, kev_list: List[Dict] = None) -> bool:
        """Verifica se um CVE está na lista KEV"""
        if kev_list is None:
            kev_list = self.fetch_kev_list()
        
        return any(kev["cve_id"] == cve_id for kev in kev_list)

