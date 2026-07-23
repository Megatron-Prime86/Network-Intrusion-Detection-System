"""
Centralized logging configuration for the NIDS project.

Every entry-point script (main.py, live_ids.py, dashboard/app.py, the
analyze_*.py utilities, etc.) should call :func:`configure_logging` once,
as early as possible, and every module should retrieve its own logger
with ``logging.getLogger(__name__)`` rather than using ``print``.

Keeping this in one place means the whole project shares a single,
consistent log format and makes it trivial to redirect output to a
file (or change the verbosity) without touching every module.
"""

from __future__ import annotations

import logging
import sys


DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
CONSOLE_REPORT_FORMAT = "%(message)s"


def configure_logging(
    level: int = logging.INFO,
    *,
    log_file: str | None = None,
    fmt: str = DEFAULT_FORMAT,
) -> None:
    """Configure the root logger for the application.

    Args:
        level: Minimum severity that will be emitted (e.g. ``logging.DEBUG``,
            ``logging.INFO``, ``logging.WARNING``).
        log_file: Optional path to also write logs to a file in addition to
            stdout. If ``None``, only stdout is used.
        fmt: The log message format string.

    This is idempotent: calling it multiple times simply resets the
    handlers instead of stacking duplicate ones.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid duplicate handlers if configure_logging() is called more than
    # once (e.g. from both a script and a module it imports).
    root_logger.handlers.clear()

    formatter = logging.Formatter(fmt)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


def get_report_logger(name: str) -> logging.Logger:
    """Return a logger pre-configured for clean, print-style CLI output.

    Used by modules that render human-facing reports (alerts, dashboards,
    IOC summaries) where timestamps/log-levels would just be noise. The
    logger still goes through the standard `logging` machinery, so output
    can be filtered, silenced, or redirected like any other log record.
    """
    logger = logging.getLogger(name)
    return logger
