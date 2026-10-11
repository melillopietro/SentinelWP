#!/usr/bin/env python3
"""
Generate CycloneDX / SPDX Software Bill of Materials (SBOM) for SentinelWP.
Inspects virtualenv packages and outputs standard CycloneDX v1.5 JSON format.
"""
import importlib.metadata
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


def generate_cyclonedx_sbom(output_path: str = "sbom.json") -> dict:
    components = []

    # Get installed distributions
    dists = sorted(importlib.metadata.distributions(), key=lambda d: d.metadata["Name"].lower())

    for dist in dists:
        meta = dist.metadata
        name = meta.get("Name", "unknown")
        version = meta.get("Version", "unknown")
        summary = meta.get("Summary", "")
        license_name = meta.get("License", "Unknown")

        # PURL format: pkg:pypi/name@version
        purl = f"pkg:pypi/{name.lower()}@{version}"

        component = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "description": summary,
            "purl": purl,
        }

        if license_name and license_name != "Unknown":
            component["licenses"] = [{"license": {"name": license_name}}]

        components.append(component)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "SentinelWP",
                    "name": "SentinelWP SBOM Generator",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": "pkg:generic/sentinelwp@ enterprise-phase5",
                "name": "SentinelWP",
                "version": "5.0.0",
                "description": "WordPress Security Assessment & Posture Management Enterprise Edition",
            },
        },
        "components": components,
    }

    out_file = Path(output_path)
    out_file.write_text(json.dumps(sbom, indent=2))
    print(f"Generated CycloneDX SBOM with {len(components)} components at {output_path}")
    return sbom


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sbom.json"
    generate_cyclonedx_sbom(out)
