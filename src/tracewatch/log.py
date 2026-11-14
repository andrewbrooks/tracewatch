"""Logging for tracewatch's own diagnostics.

The CLI's real output (reports, verdicts, progress lines) is printed. This is for the other kind of message:
something went wrong or was skipped, or a detail useful when debugging. Modules log through
`logging.getLogger(__name__)`; the CLI calls `configure` once.

Never log captured content (request or response bodies, file contents, credentials) or exception messages that may
quote it: log what happened and the exception type.
"""

from __future__ import annotations

import logging
import sys

ROOT = "tracewatch"
_FORMAT = "tracewatch: %(levelname)s: %(message)s"
_MARK = "_tracewatch_handler"


def log_unexpected(logger: logging.Logger, what: str, exc: BaseException) -> None:
    """Log an exception that a thread or hook deliberately survives. The error line names only the exception type,
    because a message can quote captured content; the full traceback is logged at debug level (-v)."""
    logger.error("%s: unexpected %s; continuing", what, type(exc).__name__)
    logger.debug("%s: traceback", what, exc_info=exc)


class _StderrHandler(logging.StreamHandler):
    """Writes to whatever sys.stderr is when a record is emitted, not when the handler was made. A handler that
    kept the first stream would write to a closed one after anything rebinds stderr (a test runner, a wrapper)."""

    def __init__(self) -> None:
        logging.Handler.__init__(self)

    @property
    def stream(self):
        return sys.stderr


def configure(verbose: bool = False) -> None:
    """Send tracewatch's log records to stderr: warnings and errors by default, everything when verbose.
    Safe to call more than once."""
    logger = logging.getLogger(ROOT)
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    if not any(getattr(h, _MARK, False) for h in logger.handlers):
        handler = _StderrHandler()
        handler.setFormatter(logging.Formatter(_FORMAT))
        setattr(handler, _MARK, True)
        logger.addHandler(handler)
