import logging
import sys

from ..config import settings

_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


def _configure_root() -> None:
    level = getattr(logging, settings.daemon_log_level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATE_FMT))
    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(handler)
    root.setLevel(level)


_configure_root()


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
