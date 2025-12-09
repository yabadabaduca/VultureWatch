"""Coletor de CVEs do NVD (National Vulnerability Database)"""
import requests
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class NVDCollector:
    """Coleta CVEs do NVD"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})
    
    def fetch_recent_cves(self, hours: int = 24, cvss_min: float = 9.0) -> List[Dict]:
        """
        Busca CVEs recentes do NVD
        
        Args:
            hours: Quantas horas para trás buscar
            cvss_min: Score CVSS mínimo
        
        Returns:
            Lista de CVEs com informações enriquecidas
        """
        cves = []
        
        # Calcula data de início
        start_date = datetime.utcnow() - timedelta(hours=hours)
        start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        # Parâmetros da busca
        params = {
            "pubStartDate": start_date_str,
            "cvssV3Severity": "CRITICAL",  # Filtra apenas críticas
        }
        
        try:
            # NVD API v2.0 usa paginação
            start_index = 0
            results_per_page = 2000
            
            while True:
                params["startIndex"] = start_index
                params["resultsPerPage"] = results_per_page
                
                response = self.session.get(self.BASE_URL, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                
                if "vulnerabilities" not in data:
                    break
                
                for item in data["vulnerabilities"]:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id")
                    
                    if not cve_id:
                        continue
                    
                    # Extrai informações do CVE
                    cve_info = self._parse_cve(cve_data, cvss_min)
                    if cve_info:
                        cves.append(cve_info)
                
                # Verifica se há mais páginas
                total_results = data.get("totalResults", 0)
                if start_index + results_per_page >= total_results:
                    break
                
                start_index += results_per_page
                
                # Rate limiting: NVD permite 50 requests/30s sem API key, 50/30s com API key
                time.sleep(0.6)  # ~1 request por segundo para segurança
            
            logger.info(f"Coletadas {len(cves)} CVEs do NVD")
            return cves
        
        except requests.RequestException as e:
            logger.error(f"Erro ao buscar CVEs do NVD: {e}")
            return []
    
    def _parse_cve(self, cve_data: Dict, cvss_min: float) -> Optional[Dict]:
        """Extrai informações relevantes de um CVE"""
        cve_id = cve_data.get("id")
        
        # Extrai descrição em inglês
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (desc.get("value", "") for desc in descriptions if desc.get("lang") == "en"),
            ""
        )
        
        # Extrai CVSS v3
        metrics = cve_data.get("metrics", {})
        cvss_v3 = None
        cvss_score = 0.0
        
        if "cvssMetricV31" in metrics:
            cvss_v3 = metrics["cvssMetricV31"][0]
            cvss_score = cvss_v3.get("cvssData", {}).get("baseScore", 0.0)
        elif "cvssMetricV30" in metrics:
            cvss_v3 = metrics["cvssMetricV30"][0]
            cvss_score = cvss_v3.get("cvssData", {}).get("baseScore", 0.0)
        elif "cvssMetricV2" in metrics:
            # Converte CVSS v2 para v3 aproximado (não ideal, mas melhor que nada)
            cvss_v2 = metrics["cvssMetricV2"][0]
            cvss_score = cvss_v2.get("cvssData", {}).get("baseScore", 0.0)
            # CVSS v2 tem escala diferente, mas vamos usar como está
        
        if cvss_score < cvss_min:
            return None
        
        # Extrai CPEs (Componentes afetados)
        configurations = cve_data.get("configurations", [])
        components = []
        
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_match = node.get("cpeMatch", [])
                for cpe in cpe_match:
                    cpe_string = cpe.get("criteria", "")
                    if cpe_string:
                        # Extrai nome do componente do CPE
                        parts = cpe_string.split(":")
                        if len(parts) >= 5:
                            component = parts[4]  # Nome do produto
                            if component and component != "*":
                                components.append({
                                    "name": component,
                                    "cpe": cpe_string,
                                    "version_range": cpe.get("versionStartIncluding") or cpe.get("versionEndIncluding", "")
                                })
        
        # Links de referência
        references = cve_data.get("references", [])
        ref_urls = [ref.get("url", "") for ref in references]
        
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_v3.get("cvssData", {}).get("vectorString", "") if cvss_v3 else "",
            "severity": cvss_v3.get("cvssData", {}).get("baseSeverity", "UNKNOWN") if cvss_v3 else "UNKNOWN",
            "components": components,
            "references": ref_urls,
            "published_date": cve_data.get("published", ""),
            "source": "nvd"
        }

