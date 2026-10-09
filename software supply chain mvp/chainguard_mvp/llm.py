"""Optional LLM integration hooks.

No provider is bundled: callers may supply an OpenAI-compatible endpoint and
API key through environment variables. Network and parsing failures return None.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

try:
    import requests
except ImportError:  # optional, requests remains the only declared dependency
    requests = None


def _complete(prompt: str, timeout: int = 30) -> str | None:
    endpoint = os.getenv("CHAINGUARD_LLM_ENDPOINT")
    key = os.getenv("CHAINGUARD_LLM_API_KEY")
    model = os.getenv("CHAINGUARD_LLM_MODEL", "gpt-4o-mini")
    if not endpoint or not key or requests is None:
        return None
    try:
        response = requests.post(
            endpoint,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0},
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
        return str(payload["choices"][0]["message"]["content"])
    except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
        return None


def _json_object(text: str | None) -> dict[str, Any] | None:
    if not text:
        return None
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.S)
        if match:
            try:
                value = json.loads(match.group(0))
                if isinstance(value, dict):
                    return value
            except json.JSONDecodeError:
                pass
    return None


def vulnerable_functions(advisory: str) -> dict[str, Any] | None:
    """Return advisory function candidates and confidence, if an LLM is configured."""
    prompt = ("Extract only explicitly vulnerable callable/function identifiers from this security advisory. "
              'Return JSON only: {"vulnerable_functions": ["name"], "confidence": 0.0}. '
              "Do not invent names. Advisory:\n" + advisory[:12000])
    result = _json_object(_complete(prompt))
    if not result:
        return None
    functions = result.get("vulnerable_functions", [])
    if not isinstance(functions, list):
        return None
    try:
        confidence = float(result.get("confidence", 0.0))
    except (TypeError, ValueError, OverflowError):
        return None
    return {"vulnerable_functions": [str(name) for name in functions if isinstance(name, str)],
            "confidence": max(0.0, min(1.0, confidence))}


def package_risk(name: str, ecosystem: str) -> dict[str, Any] | None:
    prompt = ("Assess whether this dependency name looks hallucinated, mistyped, or suspicious. "
              'Return JSON only: {"risk": 0, "reason": "short reason"}. '
              f"Ecosystem: {ecosystem}\nPackage: {name}")
    result = _json_object(_complete(prompt, timeout=15))
    if not result:
        return None
    try:
        risk = max(0, min(10, int(result.get("risk", 0))))
    except (ValueError, TypeError):
        return None
    return {"risk": risk, "reason": str(result.get("reason", ""))[:500]}
