"""Catch stale package/roadmap version claims without importing the application."""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def test_package_uses_application_version():
    tree = ast.parse((ROOT / "blocklist_import.py").read_text())
    versions = [ast.literal_eval(n.value) for n in tree.body
                if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "__version__" for t in n.targets)]
    assert len(versions) == 1
    assert re.fullmatch(r"\d+\.\d+\.\d+", versions[0])
    metadata = (ROOT / "pyproject.toml").read_text()
    assert 'version = {attr = "blocklist_import.__version__"}' in metadata
    assert 'dynamic = ["version"]' in metadata
    assert f"**Development version:** v{versions[0]}" in (ROOT / "ROADMAP.md").read_text()


def test_package_description_does_not_hardcode_feed_count():
    metadata = (ROOT / "pyproject.toml").read_text()
    description = re.search(r'^description = "(.*)"$', metadata, re.M).group(1)
    assert not re.search(r"\d+.*feeds", description)
