"""Make ``src/`` importable during tests without an editable install.

The scope module is pure stdlib (no husk import), so its tests run with zero
setup -- important for CI and for a quick local check. Once a test needs the
kernel, install both packages editable: ``pip install -e ../husk && pip install -e .``
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))
