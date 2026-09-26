"""Load a tools/*.py script as a module for its tests: the scripts have hyphens in their names, so
they cannot be imported by name."""
import importlib.util
import os

TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def load(script):
    path = os.path.join(TOOLS_DIR, script)
    spec = importlib.util.spec_from_file_location(script.replace("-", "_").replace(".py", ""), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
