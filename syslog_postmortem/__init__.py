__version__ = "1.1.1"

from .cli import main  # noqa: E402  (after __version__: cli imports it)

__all__ = ["main", "__version__"]
