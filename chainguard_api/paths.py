"""Path security for untrusted repository identifiers and locations.

Repositories arrive from callers, so every path is canonicalised (``resolve()``
normalises ``..`` and follows symlinks/junctions) and then required to live
inside the configured allowed root. Repository *ids* are also untrusted: they
become directory names, so they are restricted to a safe character set.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

REPOSITORY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

INVALID_REPOSITORY = "INVALID_REPOSITORY"


class PathValidationError(ValueError):
    """Raised when a repository path or id is not acceptable."""

    def __init__(self, message: str, code: str = INVALID_REPOSITORY) -> None:
        super().__init__(message)
        self.code = code


def validate_repository_id(raw: str) -> str:
    value = (raw or "").strip()
    if not REPOSITORY_ID_PATTERN.match(value):
        raise PathValidationError(
            "repository id must be 1-64 characters of [A-Za-z0-9._-] and start "
            "with a letter or digit", code="INVALID_REPOSITORY_ID")
    if ".." in value or "/" in value or "\\" in value:
        raise PathValidationError("repository id must not contain path separators",
                                  code="INVALID_REPOSITORY_ID")
    return value


def canonicalize(path: str | Path) -> Path:
    """Resolve symlinks/junctions and normalise ``..`` (lexically if missing)."""
    return Path(path).expanduser().resolve()


def _strip_extended(text: str) -> str:
    """Drop Windows' extended-length prefix so forms compare equal.

    ``Path.resolve()`` intermittently returns ``\\\\?\\C:\\...`` when it has to
    resolve through a directory that exists at that instant (a race in fleet
    scans, where sibling output directories are being created concurrently).
    Comparing that against a plain ``C:\\...`` root would wrongly report an
    escape.
    """
    if text.startswith("\\\\?\\"):
        text = text[4:]
    return text


def _comparable(path: Path) -> Path:
    return Path(os.path.normpath(_strip_extended(str(path))))


def _is_within(candidate: Path, allowed: Path) -> bool:
    left, right = _comparable(candidate), _comparable(allowed)
    if os.name == "nt":
        left_s, right_s = str(left).lower(), str(right).lower()
    else:
        left_s, right_s = str(left), str(right)
    if left_s == right_s:
        return True
    return left_s.startswith(right_s.rstrip(os.sep) + os.sep)


def validate_repository_path(raw: str | Path, allowed_root: str | Path) -> Path:
    """Return the canonical repository path or raise PathValidationError."""
    if raw is None or str(raw).strip() == "":
        raise PathValidationError("repository path is required")
    if "\x00" in str(raw):
        raise PathValidationError("repository path contains a NUL byte")
    allowed = canonicalize(allowed_root)
    candidate = canonicalize(raw)
    if not _is_within(candidate, allowed):
        raise PathValidationError(
            f"repository path escapes the allowed root: {_comparable(candidate)}")
    if not candidate.is_dir():
        raise PathValidationError(f"repository path is not a directory: {_comparable(candidate)}")
    return _comparable(candidate)


def validate_output_directory(raw: str | Path, allowed_root: str | Path) -> Path:
    """Scan outputs must stay inside the allowed root too (defence in depth)."""
    allowed = canonicalize(allowed_root)
    candidate = canonicalize(raw)
    if not _is_within(candidate, allowed):
        raise PathValidationError(
            f"output directory escapes the allowed root: {_comparable(candidate)}",
            code="INVALID_OUTPUT_DIRECTORY")
    return _comparable(candidate)


def is_within_root(candidate: str | Path, allowed_root: str | Path) -> bool:
    """Public containment test used by read-only artifact serving.

    Symlinks are resolved first, so a link that points outside ``allowed_root``
    is rejected; the ``\\?\`` prefix and case differences on Windows are
    normalised by the same comparison the repository validators use.
    """
    return _is_within(canonicalize(candidate), canonicalize(allowed_root))
