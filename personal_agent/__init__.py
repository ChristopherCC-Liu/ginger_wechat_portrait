"""Local-first personal chat agent primitives for Ginger exports."""

from importlib.metadata import PackageNotFoundError, version

from .builder import build_bundle

__all__ = ["build_bundle"]

try:
    __version__ = version("ginger-personal-agent")
except PackageNotFoundError:
    __version__ = "0+unknown"
