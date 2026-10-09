import subprocess
from pathlib import Path

from chainguard_mvp.cli import _diff_added_packages
from chainguard_mvp.parsers import discover_manifests


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def test_diff_mode_returns_new_and_upgraded_dependencies(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"kept":"1.0.0","upgraded":"1.0.0"}}', encoding="utf-8")
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    git(tmp_path, "config", "user.name", "Test")
    git(tmp_path, "add", "package.json")
    git(tmp_path, "commit", "-qm", "base")
    base = git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"kept":"1.0.0","upgraded":"2.0.0","added":"1.0.0"}}', encoding="utf-8")
    added = _diff_added_packages(tmp_path, discover_manifests(tmp_path), base)
    assert {(item["name"], item["version"]) for item in added} == {
        ("upgraded", "2.0.0"), ("added", "1.0.0")}
