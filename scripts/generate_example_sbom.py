#!/usr/bin/env python3
"""
Script de exemplo para gerar um SBOM simples para testes
"""
import json
from pathlib import Path

# Exemplo de SBOM CycloneDX
example_sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "components": [
        {
            "type": "library",
            "name": "log4j-core",
            "version": "2.17.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0"
        },
        {
            "type": "library",
            "name": "spring-core",
            "version": "5.3.21",
            "purl": "pkg:maven/org.springframework/spring-core@5.3.21"
        },
        {
            "type": "library",
            "name": "django",
            "version": "4.0.0",
            "purl": "pkg:pypi/django@4.0.0"
        },
        {
            "type": "library",
            "name": "express",
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0"
        },
        {
            "type": "library",
            "name": "openssl",
            "version": "1.1.1",
            "purl": "pkg:generic/openssl@1.1.1"
        }
    ]
}

def main():
    """Gera arquivo SBOM de exemplo"""
    sbom_dir = Path("./sbom")
    sbom_dir.mkdir(exist_ok=True)
    
    sbom_file = sbom_dir / "example-sbom.json"
    
    with open(sbom_file, "w", encoding="utf-8") as f:
        json.dump(example_sbom, f, indent=2)
    
    print(f"✅ SBOM de exemplo criado em: {sbom_file}")
    print("\nComponentes incluídos:")
    for component in example_sbom["components"]:
        print(f"  - {component['name']} {component['version']}")

if __name__ == "__main__":
    main()

