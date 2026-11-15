from __future__ import annotations


class MessageLayoutError(ValueError):
    """The stored fields contradict a declared message calling convention."""
