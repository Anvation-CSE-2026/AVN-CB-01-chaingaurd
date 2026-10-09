"""Path security: traversal, absolute-outside-root, symlink escape, ids."""
from __future__ import annotations

import os
import pathlib
from pathlib import Path

import pytest

from chainguard_api.paths import (
    PathValidationError,
    validate_output_directory,
    validate_repository_id,
    validate_repository_path,
)


def test_rejects_relative_traversal(tmp_path: Path, allowed_root: Path) -> None:
    with pytest.raises(PathValidationError) as excinfo:
        validate_repository_path("../escape", allowed_root)
    assert excinfo.value.code == "INVALID_REPOSITORY"


def test_rejects_absolute_path_outside_allowed_root(tmp_path: Path,
                                                    allowed_root: Path) -> None:
    outside = tmp_path / "outside"
    with pytest.raises(PathValidationError):
        validate_repository_path(str(outside), allowed_root)


def test_rejects_traversal_inside_string(tmp_path: Path, allowed_root: Path) -> None:
    sneaky = str(allowed_root / "repo-a" / ".." / ".." / "outside")
    with pytest.raises(PathValidationError):
        validate_repository_path(sneaky, allowed_root)


def test_accepts_path_inside_allowed_root(allowed_root: Path) -> None:
    resolved = validate_repository_path(str(allowed_root / "repo-a"), allowed_root)
    assert resolved == (allowed_root / "repo-a").resolve()
    assert resolved.is_relative_to(allowed_root.resolve())


def test_rejects_symlink_escape(tmp_path: Path, allowed_root: Path) -> None:
    outside = tmp_path / "outside"
    link = allowed_root / "sneaky-link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - platform limits
        pytest.skip(f"symlinks unavailable on this host: {exc}")
    with pytest.raises(PathValidationError):
        validate_repository_path(str(link), allowed_root)


def test_rejects_nonexistent_directory(allowed_root: Path) -> None:
    with pytest.raises(PathValidationError):
        validate_repository_path(str(allowed_root / "does-not-exist"), allowed_root)


def test_rejects_empty_and_nul_paths(allowed_root: Path) -> None:
    with pytest.raises(PathValidationError):
        validate_repository_path("", allowed_root)
    with pytest.raises(PathValidationError):
        validate_repository_path("bad\x00path", allowed_root)


def test_output_directory_must_stay_inside_root(tmp_path: Path,
                                                allowed_root: Path) -> None:
    with pytest.raises(PathValidationError) as excinfo:
        validate_output_directory(str(tmp_path / "elsewhere"), allowed_root)
    assert excinfo.value.code == "INVALID_OUTPUT_DIRECTORY"
    inside = validate_output_directory(str(allowed_root / "scan_workspace" / "x"),
                                       allowed_root)
    assert inside.is_relative_to(allowed_root.resolve())


@pytest.mark.parametrize("raw", ["../evil", "a/b", "a\\b", "..", "", " ",
                                 "-leading-dash", "x" * 65, "with space"])
def test_rejects_unsafe_repository_ids(raw: str) -> None:
    with pytest.raises(PathValidationError):
        validate_repository_id(raw)


@pytest.mark.parametrize("raw", ["repo-a", "repo_a.1", "R2D2", "a" * 64])
def test_accepts_safe_repository_ids(raw: str) -> None:
    assert validate_repository_id(raw) == raw


def test_accepts_forward_slash_path_inside_root(allowed_root: Path) -> None:
    forward = str(allowed_root / "repo-a").replace("\\", "/")
    assert validate_repository_path(forward, allowed_root) == (allowed_root / "repo-a").resolve()


@pytest.mark.skipif(os.name != "nt", reason="backslashes are literal filename bytes on POSIX")
def test_rejects_mixed_separator_traversal(tmp_path: Path, allowed_root: Path) -> None:
    """Alternating separators must not slip past containment."""
    mixed = str(allowed_root).replace("\\", "/") + "/repo-a/.." + os.sep + ".." + os.sep + "outside"
    with pytest.raises(PathValidationError):
        validate_repository_path(mixed, allowed_root)
    forward_mixed = str(allowed_root).replace("\\", "/") + "/repo-a/../.." + os.sep + "outside"
    with pytest.raises(PathValidationError):
        validate_repository_path(forward_mixed, allowed_root)


@pytest.mark.skipif(os.name != "nt", reason="extended-length paths are Windows-only")
def test_rejects_extended_length_path_outside_root(tmp_path: Path, allowed_root: Path) -> None:
    outside = "\\\\?\\" + str(tmp_path / "outside")
    with pytest.raises(PathValidationError):
        validate_repository_path(outside, allowed_root)
    inside = "\\\\?\\" + str(allowed_root / "repo-a")
    assert validate_repository_path(inside, allowed_root) == (allowed_root / "repo-a").resolve()


@pytest.mark.skipif(os.name != "nt", reason="extended-length paths are Windows-only")
def test_extended_length_prefix_is_normalised_before_containment() -> None:
    """Path.resolve() can return \\\\?\\C:\\... while the root stays plain."""
    from chainguard_api.paths import _is_within

    prefix = "\\" * 2 + "?" + "\\"
    assert _is_within(pathlib.Path(prefix + r"C:\root\child"),
                      pathlib.Path(r"C:\root")) is True
    assert _is_within(pathlib.Path(prefix + r"C:\other"),
                      pathlib.Path(r"C:\root")) is False
    assert _is_within(pathlib.Path(r"C:\root\child"),
                      pathlib.Path(prefix + r"C:\root")) is True
