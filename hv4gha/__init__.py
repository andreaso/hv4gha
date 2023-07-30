"""Package info, etc"""

import importlib.metadata

from .entry import import_app_key, issue_access_token
from .gh import TokenResponse

__all__ = ["import_app_key", "issue_access_token", "TokenResponse"]

try:
    __version__ = importlib.metadata.version(__package__ or __name__)
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0"
