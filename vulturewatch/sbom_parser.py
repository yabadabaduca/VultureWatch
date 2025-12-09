"""Parser de SBOM (CycloneDX e SPDX)"""
import json
from pathlib import Path
from typing import List, Dict, Set, Optional
import logging
from .security import sanitize_path

logger = logging.getLogger(__name__)


class SBOMParser:
    """Parser para arquivos SBOM"""
    
    def __init__(self, sbom_path: str, format: str = "cyclonedx-json", base_dir: Optional[Path] = None):
        # Sanitiza caminho para prevenir path traversal
        sanitized_path = sanitize_path(sbom_path, base_dir)
        if sanitized_path is None:
            raise ValueError(f"Caminho SBOM inválido ou fora do diretório permitido: {sbom_path}")
        
        self.sbom_path = sanitized_path
        self.format = format.lower()
        self.components = set()
    
    def parse(self) -> Set[str]:
        """
        Parse o SBOM e retorna conjunto de componentes
        
        Returns:
            Set com nomes de componentes normalizados
        """
        if not self.sbom_path.exists():
            logger.warning(f"Arquivo SBOM não encontrado: {self.sbom_path}")
            return set()
        
        if self.sbom_path.is_file():
            return self._parse_file(self.sbom_path)
        elif self.sbom_path.is_dir():
            # Parse múltiplos arquivos
            components = set()
            base_resolved = self.sbom_path.resolve()
            for sbom_file in self.sbom_path.glob("*.json"):
                # Valida que arquivo está dentro do diretório permitido
                try:
                    file_resolved = sbom_file.resolve()
                    # Verifica que o arquivo está dentro do diretório base
                    file_resolved.relative_to(base_resolved)
                    components.update(self._parse_file(sbom_file))
                except ValueError:
                    # Arquivo está fora do diretório permitido, ignora
                    logger.warning(f"Arquivo SBOM fora do diretório permitido ignorado: {sbom_file}")
            return components
        else:
            logger.warning(f"Caminho SBOM inválido: {self.sbom_path}")
            return set()
    
    def _parse_file(self, file_path: Path) -> Set[str]:
        """Parse um arquivo SBOM específico"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if self.format == "cyclonedx-json":
                return self._parse_cyclonedx(data)
            elif self.format == "spdx-json":
                return self._parse_spdx(data)
            else:
                logger.warning(f"Formato SBOM não suportado: {self.format}")
                return set()
        
        except Exception as e:
            logger.error(f"Erro ao parsear SBOM {file_path}: {e}")
            return set()
    
    def _parse_cyclonedx(self, data: Dict) -> Set[str]:
        """Parse formato CycloneDX"""
        components = set()
        
        # CycloneDX pode ter 'components' ou 'bom-ref'
        bom_components = data.get("components", [])
        
        for component in bom_components:
            name = component.get("name", "").lower()
            if name:
                components.add(name)
                
                # Também adiciona variações comuns
                # Ex: "spring-core" -> "spring", "springframework"
                if "-" in name:
                    parts = name.split("-")
                    components.update(parts)
        
        logger.info(f"Extraídos {len(components)} componentes do SBOM CycloneDX")
        return components
    
    def _parse_spdx(self, data: Dict) -> Set[str]:
        """Parse formato SPDX"""
        components = set()
        
        # SPDX tem 'packages'
        packages = data.get("packages", [])
        
        for package in packages:
            name = package.get("name", "").lower()
            if name:
                components.add(name)
                
                # Extrai nome do pacote (pode ter namespace)
                if "/" in name:
                    parts = name.split("/")
                    components.update(parts)
        
        logger.info(f"Extraídos {len(components)} componentes do SBOM SPDX")
        return components
    
    def is_component_used(self, component_name: str) -> bool:
        """Verifica se um componente está no SBOM"""
        if not self.components:
            self.components = self.parse()
        
        component_lower = component_name.lower()
        
        # Verificação exata
        if component_lower in self.components:
            return True
        
        # Verificação parcial (ex: "log4j-core" contém "log4j")
        for sbom_component in self.components:
            if component_lower in sbom_component or sbom_component in component_lower:
                return True
        
        return False

