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


def _py_modules():
    metadata = (ROOT / "pyproject.toml").read_text()
    m = re.search(r"^py-modules = \[(.*)\]$", metadata, re.M)
    assert m, "py-modules line not found in pyproject.toml"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def test_packaging_includes_every_application_module():
    """--impact-preview and --setup are lazy imports; the wheel and the
    Docker image must ship those modules or the flags fail at runtime."""
    tree = ast.parse((ROOT / "blocklist_import.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
    app_modules = {name for name in imported
                   if (ROOT / f"{name}.py").exists()}
    modules = _py_modules()
    missing = app_modules - modules
    assert not missing, f"app modules missing from py-modules: {sorted(missing)}"
    dockerfile = (ROOT / "Dockerfile").read_text()
    absent = [name for name in sorted(app_modules)
              if f"{name}.py" not in dockerfile]
    assert not absent, f"app modules not copied in Dockerfile: {absent}"
