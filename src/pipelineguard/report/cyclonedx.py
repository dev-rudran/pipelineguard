"""CycloneDX 1.5 JSON generation."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from .. import __version__
from ..models import Component, isoformat

SPEC_VERSION = "1.5"
SPDX_LIKE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")


def _license_choice(value: str) -> dict[str, Any]:
    cleaned = value.strip()
    if not cleaned:
        return {}
    if " OR " in cleaned or " AND " in cleaned or cleaned.startswith("("):
        return {"expression": cleaned}
    if SPDX_LIKE.match(cleaned) and len(cleaned) <= 64:
        return {"license": {"id": cleaned}}
    return {"license": {"name": cleaned}}


def _component_entry(component: Component) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "library",
        "bom-ref": component.purl,
        "name": component.name,
        "purl": component.purl,
    }
    if component.version:
        entry["version"] = component.version
    if component.license:
        choice = _license_choice(component.license)
        if choice:
            entry["licenses"] = [choice]
    properties = [
        {"name": "pipelineguard:ecosystem", "value": component.ecosystem},
        {"name": "pipelineguard:direct", "value": "true" if component.direct else "false"},
    ]
    if component.source:
        properties.append({"name": "pipelineguard:source", "value": component.source})
    entry["properties"] = properties
    return entry


def _serial_number(components: Iterable[Component]) -> str:
    material = "\n".join(
        sorted(f"{item.purl}|{item.license or ''}|{item.direct}" for item in components)
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'pipelineguard:' + digest)}"


def build_bom(
    components: Iterable[Component],
    target_name: str = "repository",
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """Build a deterministic CycloneDX 1.5 document.

    ``timestamp`` defaults to the current UTC time; tests can inject a fixed
    value. Ordering is by purl so repeated runs produce identical bytes apart
    from the timestamp.
    """
    ordered = sorted(
        components,
        key=lambda item: (item.purl, item.name.lower(), item.version),
    )
    moment = timestamp or datetime.now(timezone.utc)
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial_number(ordered),
        "version": 1,
        "metadata": {
            "timestamp": isoformat(moment),
            "tools": [
                {
                    "vendor": "dev-rudran",
                    "name": "pipelineguard",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": "pipelineguard-root",
                "name": target_name or "repository",
            },
        },
        "components": [_component_entry(component) for component in ordered],
    }
    if ordered:
        bom["dependencies"] = [
            {
                "ref": "pipelineguard-root",
                "dependsOn": [item.purl for item in ordered if item.direct],
            }
        ]
    return bom


def to_json(bom: dict[str, Any]) -> str:
    return json.dumps(bom, indent=2, ensure_ascii=False) + "\n"
