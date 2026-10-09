"""Best-effort source reachability analysis for vulnerable dependencies."""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", ".tox", "dist", "build"}
PYPI_IMPORT_OVERRIDES = {
    "pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"],
    "scikit-learn": ["sklearn"], "opencv-python": ["cv2"],
    "python-dateutil": ["dateutil"], "attrs": ["attr"],
    "protobuf": ["google"], "pyjwt": ["jwt"], "django": ["django"],
}


def import_names(package: dict[str, str]) -> list[str]:
    name = package["name"]
    if package["ecosystem"] == "PyPI":
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        return PYPI_IMPORT_OVERRIDES.get(normalized, [normalized.replace("-", "_")])
    if package["ecosystem"] == "npm":
        return [name]
    return [name.split(":", 1)[-1]]


def _source_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            yield root
        return
    for current, dirs, files in __import__("os").walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for filename in files:
            path = Path(current) / filename
            if path.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
                yield path


def _python_imports(path: Path, aliases: dict[str, str]) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except (SyntaxError, OSError, ValueError):
        return []
    evidence = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                local = alias.asname or root
                aliases[local] = root
                evidence.append({"line": node.lineno, "kind": "import", "name": alias.name})
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".", 1)[0]
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{node.module}.{alias.name}" if node.module else alias.name
                aliases.setdefault(f"{root}.{local}", root)
                evidence.append({"line": node.lineno, "kind": "import", "name": f"{node.module or ''}.{alias.name}".strip(".")})
    return evidence


def _python_calls(path: Path, vulnerable_functions: list[str], aliases: dict[str, str]) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except (SyntaxError, OSError, ValueError):
        return []
    exact_targets = {x for x in vulnerable_functions if x}
    simple_targets = {x for x in exact_targets if "." not in x}
    if not exact_targets:
        return []
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            called = func.id
            mapped = aliases.get(called)
            matched = (called in simple_targets or mapped in exact_targets
                       or (mapped and mapped.rsplit(".", 1)[-1] in simple_targets))
        elif isinstance(func, ast.Attribute):
            called = func.attr
            chain = func.value.id if isinstance(func.value, ast.Name) else ""
            mapped = aliases.get(chain)
            qualified = f"{chain}.{called}" if chain else called
            mapped_name = f"{mapped}.{called}" if mapped else qualified
            matched = (called in simple_targets or qualified in exact_targets
                       or mapped_name in exact_targets)
            if isinstance(func.value, ast.Attribute):
                prefix = func.value.attr
                chain = func.value.value.id if isinstance(func.value.value, ast.Name) else ""
                mapped = aliases.get(chain)
                qualified = f"{chain}.{prefix}.{called}" if chain else f"{prefix}.{called}"
                mapped_name = f"{mapped}.{prefix}.{called}" if mapped else qualified
                matched = matched or qualified in exact_targets or mapped_name in exact_targets
        else:
            called = ""
            matched = False
        if matched:
            found.append({"line": node.lineno, "kind": "call", "name": called})
    return found


def analyze_package(root: str | Path, package: dict[str, str], vulnerable_functions: list[str]) -> dict[str, Any]:
    """Return imported/call evidence and whether package code is reachable."""
    root = Path(root)
    names = import_names(package)
    import_evidence: list[dict[str, Any]] = []
    call_evidence: list[dict[str, Any]] = []
    files = list(_source_files(root))
    aliases_by_file: dict[Path, dict[str, str]] = {}
    for file in files:
        if file.suffix.lower() != ".py":
            continue
        aliases: dict[str, str] = {}
        imports = _python_imports(file, aliases)
        relevant = [item for item in imports if item["name"].split(".", 1)[0] in names]
        if relevant:
            aliases_by_file[file] = aliases
            for item in relevant:
                import_evidence.append({"file": str(file), **item})
    for file in files:
        if file.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            try:
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for name in names:
                patterns = [rf"\bimport\s+(?:[^;]*?\s+from\s+)?['\"]{re.escape(name)}(?:/[^'\"]*)?['\"]",
                            rf"\brequire\s*\(\s*['\"]{re.escape(name)}(?:/[^'\"]*)?['\"]\s*\)"]
                for pattern in patterns:
                    for match in re.finditer(pattern, text):
                        line = text.count("\n", 0, match.start()) + 1
                        import_evidence.append({"file": str(file), "line": line, "kind": "import", "name": name})
                        break
        if file.suffix.lower() == ".py":
            aliases = aliases_by_file.get(file)
            if aliases:
                for item in _python_calls(file, vulnerable_functions, aliases):
                    call_evidence.append({"file": str(file), **item})
        elif file.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"} and vulnerable_functions:
            try:
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for function in vulnerable_functions:
                identifier = function.rsplit(".", 1)[-1]
                for match in re.finditer(rf"\b{re.escape(identifier)}\s*\(", text):
                    line = text.count("\n", 0, match.start()) + 1
                    call_evidence.append({"file": str(file), "line": line, "kind": "call", "name": identifier})
    return {"imported": bool(import_evidence), "import_evidence": import_evidence,
            "call_evidence": call_evidence,
            "status": "affected" if call_evidence or (import_evidence and not vulnerable_functions)
                      else "not_affected",
            "justification": "vulnerable_code_not_present" if not import_evidence
                            else ("vulnerable_code_not_in_execute_path" if not call_evidence and vulnerable_functions else None)}
