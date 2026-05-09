from pathlib import Path
import sys


def project_root():
    return Path(__file__).resolve().parents[2]


def is_frozen():
    return bool(getattr(sys, "frozen", False))


def resource_root():
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS"))
    return project_root()


def runtime_root():
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path.cwd()


def resource_path(*parts):
    return resource_root().joinpath(*parts)


def runtime_path(*parts):
    return runtime_root().joinpath(*parts)