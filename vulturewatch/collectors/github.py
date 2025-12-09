"""Coletor de PoCs e exploits do GitHub"""
import requests
from typing import List, Dict, Optional
import logging
from ..security import validate_cve_id

logger = logging.getLogger(__name__)


class GitHubCollector:
    """Coleta PoCs e exploits do GitHub"""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": f"token {token}"})
    
    def search_pocs(self, cve_id: str) -> List[Dict]:
        """
        Busca PoCs e exploits no GitHub para um CVE
        
        Returns:
            Lista de PoCs encontrados
        """
        # Valida CVE ID
        if not validate_cve_id(cve_id):
            logger.warning(f"CVE ID inválido: {cve_id}")
            return []
        
        pocs = []
        
        try:
            # Busca por repositórios que mencionam o CVE
            query = f"{cve_id} exploit OR poc OR proof"
            params = {
                "q": query,
                "sort": "updated",
                "order": "desc",
                "per_page": 10
            }
            
            response = self.session.get(f"{self.BASE_URL}/search/repositories", 
                                       params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            items = data.get("items", [])
            
            for item in items:
                # Avalia maturidade baseado em indicadores
                maturity_level = self._assess_maturity(item)
                
                if maturity_level >= 1:  # Só inclui se tiver alguma maturidade
                    pocs.append({
                        "name": item.get("name", ""),
                        "full_name": item.get("full_name", ""),
                        "url": item.get("html_url", ""),
                        "description": item.get("description", ""),
                        "stars": item.get("stargazers_count", 0),
                        "updated_at": item.get("updated_at", ""),
                        "maturity_level": maturity_level,
                        "source": "github"
                    })
            
            logger.debug(f"Encontrados {len(pocs)} PoCs no GitHub para {cve_id}")
            return pocs
        
        except requests.RequestException as e:
            logger.error(f"Erro ao buscar PoCs no GitHub para {cve_id}: {e}")
            return []
    
    def _assess_maturity(self, repo: Dict) -> int:
        """
        Avalia maturidade baseado em indicadores do repositório
        
        Returns:
            0-3: nível de maturidade
        """
        name = repo.get("name", "").lower()
        description = repo.get("description", "").lower()
        
        # Indicadores de maturidade alta
        if any(keyword in name or keyword in description 
               for keyword in ["metasploit", "exploit", "module"]):
            return 3
        
        # Indicadores de PoC funcional
        if any(keyword in name or keyword in description 
               for keyword in ["poc", "proof-of-concept", "exploit", "cve"]):
            return 2
        
        # Caso padrão
        return 1

