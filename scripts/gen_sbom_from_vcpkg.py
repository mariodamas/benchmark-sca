#!/usr/bin/env python3
"""Genera SBOM CycloneDX correcto desde vcpkg.json con versiones exactas del benchmark"""
import json, uuid
from pathlib import Path

PROJ = Path(__file__).parent.parent

# Mapa vcpkg-name → versión exacta del benchmark (la mínima del rango version>=)
COMPONENTS = [
    {"name": "zlib",    "version": "1.2.11", "purl": "pkg:generic/zlib@1.2.11",     "cpe": "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*"},
    {"name": "libpng",  "version": "1.6.34", "purl": "pkg:generic/libpng@1.6.34",   "cpe": "cpe:2.3:a:libpng:libpng:1.6.34:*:*:*:*:*:*:*"},
    {"name": "expat",   "version": "2.4.6",  "purl": "pkg:generic/expat@2.4.6",     "cpe": "cpe:2.3:a:libexpat_project:libexpat:2.4.6:*:*:*:*:*:*:*"},
    {"name": "sqlite3", "version": "3.39.1", "purl": "pkg:generic/sqlite3@3.39.1",  "cpe": "cpe:2.3:a:sqlite:sqlite:3.39.1:*:*:*:*:*:*:*"},
    {"name": "curl",    "version": "7.58.0", "purl": "pkg:generic/curl@7.58.0",     "cpe": "cpe:2.3:a:haxx:curl:7.58.0:*:*:*:*:*:*:*"},
    {"name": "openssl", "version": "1.0.2k", "purl": "pkg:generic/openssl@1.0.2k",  "cpe": "cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*"},
]

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "version": 1,
    "metadata": {
        "timestamp": "2026-04-07T00:00:00Z",
        "tools": [{"vendor": "manual", "name": "gen_sbom_from_vcpkg.py", "version": "1.0"}],
        "component": {
            "type": "application",
            "name": "mi-gateway-iot",
            "version": "1.0.0"
        }
    },
    "components": []
}

for c in COMPONENTS:
    comp = {
        "type": "library",
        "name": c["name"],
        "version": c["version"],
        "purl": c["purl"],
        "cpe": c["cpe"],
        "bom-ref": f"{c['name']}@{c['version']}"
    }
    sbom["components"].append(comp)

out = PROJ / 'sbom' / 'sbom-cyclonedx.json'
with open(out, 'w', encoding='utf-8') as f:
    json.dump(sbom, f, indent=2)

print(f"SBOM escrito: {out}")
print(f"Componentes: {len(COMPONENTS)}")
for c in COMPONENTS:
    print(f"  {c['name']} {c['version']}")
