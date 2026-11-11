"""Darshan I/O agent tools: the filled two-layer schema, exact facts and cards, and exact
arithmetic, so an agent answers from numbers retrieved from the log.

PyDarshan is imported only when a log is opened, so toolbox and calc work without it."""
__version__ = "1.0.0"


def __getattr__(name):
    if name in ("Session", "fill_schema"):
        from . import session
        return getattr(session, name)
    raise AttributeError(name)
