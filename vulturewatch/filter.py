"""Módulo de filtragem e enriquecimento de CVEs"""
from typing import List, Dict, Optional
import logging
from .collectors.kev import KEVCollector
from .collectors.exploit_db import ExploitDBCollector
from .collectors.github import GitHubCollector
from .sbom_parser import SBOMParser

logger = logging.getLogger(__name__)


class CVEFilter:
    """Filtra e enriquece CVEs baseado em critérios"""
    
    def __init__(self, config: Dict, sbom_parser: Optional[SBOMParser] = None):
        self.config = config
        self.cvss_min = config.get("cvss_min_score", 9.0)
        self.maturity_min = config.get("maturity_min_level", 2)
        self.filters = config.get("filters", {})
        self.sbom_parser = sbom_parser
        
        # Inicializa coletores
        self.kev_collector = KEVCollector()
        self.exploit_db_collector = ExploitDBCollector()
        self.github_collector = GitHubCollector()
        
        # Cache da lista KEV
        self._kev_list = None
    
    def filter_critical_cves(self, cves: List[Dict]) -> List[Dict]:
        """
        Filtra CVEs críticas que atendem aos critérios
        
        Args:
            cves: Lista de CVEs brutas
        
        Returns:
            Lista de CVEs filtradas e enriquecidas
        """
        filtered = []
        
        # Carrega lista KEV uma vez
        if self._kev_list is None:
            self._kev_list = self.kev_collector.fetch_kev_list()
        
        for cve in cves:
            # Enriquece CVE com informações de exploit
            enriched = self._enrich_cve(cve)
            
            # Verifica se atende aos critérios
            if self._meets_criteria(enriched):
                filtered.append(enriched)
        
        logger.info(f"Filtradas {len(filtered)} CVEs críticas de {len(cves)} total")
        return filtered
    
    def _enrich_cve(self, cve: Dict) -> Dict:
        """Enriquece CVE com informações de exploits e PoCs"""
        cve_id = cve.get("cve_id", "")
        
        # Verifica se está na lista KEV
        is_kev = self.kev_collector.is_kev(cve_id, self._kev_list)
        
        # Busca exploits no Exploit-DB
        exploit_db_exploits = self.exploit_db_collector.search_exploits(cve_id)
        
        # Busca PoCs no GitHub
        github_pocs = self.github_collector.search_pocs(cve_id)
        
        # Determina se tem exploit público
        has_public_exploit = len(exploit_db_exploits) > 0
        
        # Determina se tem PoC pública
        has_public_poc = len(github_pocs) > 0 or len(exploit_db_exploits) > 0
        
        # Calcula maturidade máxima
        max_maturity = 0
        if exploit_db_exploits:
            max_maturity = max(exp.get("maturity_level", 0) for exp in exploit_db_exploits)
        if github_pocs:
            max_maturity = max(max_maturity, max(poc.get("maturity_level", 0) for poc in github_pocs))
        
        # Coleta links de exploits
        exploit_links = []
        for source_name, items in [("exploit_db", exploit_db_exploits), ("github", github_pocs)]:
            for item in items:
                exploit_links.append({
                    "url": item.get("url", ""),
                    "maturity": item.get("maturity_level", 0),
                    "source": source_name
                })
        
        # Adiciona informações ao CVE
        cve["has_public_exploit"] = has_public_exploit
        cve["has_public_poc"] = has_public_poc
        cve["is_kev"] = is_kev
        cve["max_maturity_level"] = max_maturity
        cve["exploit_links"] = exploit_links
        
        return cve
    
    def _meets_criteria(self, cve: Dict) -> bool:
        """Verifica se CVE atende aos critérios de filtragem"""
        # Verifica CVSS mínimo
        cvss_score = cve.get("cvss_score", 0.0)
        
        # Se está na lista KEV e configurado para incluir mesmo abaixo do mínimo
        include_kev = self.filters.get("include_kev_even_if_cvss_below_min", True)
        if cve.get("is_kev") and include_kev:
            # KEV sempre passa, mesmo se CVSS menor
            pass
        elif cvss_score < self.cvss_min:
            return False
        
        # Verifica se tem exploit/PoC/KEV (pelo menos um)
        has_exploit = cve.get("has_public_exploit", False)
        has_poc = cve.get("has_public_poc", False)
        is_kev = cve.get("is_kev", False)
        
        if not (has_exploit or has_poc or is_kev):
            return False
        
        # Verifica maturidade mínima
        max_maturity = cve.get("max_maturity_level", 0)
        if max_maturity < self.maturity_min:
            # Se não tem exploit/PoC maduro, só passa se for KEV
            if not is_kev:
                return False
        
        # Verifica se componente está no SBOM (se configurado)
        only_sbom = self.filters.get("only_components_in_sbom", False)
        if only_sbom and self.sbom_parser:
            components = cve.get("components", [])
            if not components:
                return False
            
            # Verifica se pelo menos um componente está no SBOM
            component_found = False
            for component in components:
                component_name = component.get("name", "")
                if component_name and self.sbom_parser.is_component_used(component_name):
                    component_found = True
                    # Adiciona informação de onde o componente é usado
                    cve["used_in"] = component_name
                    break
            
            if not component_found:
                return False
        
        return True

