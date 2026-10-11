"""GROSSE FUGUE — PII redaction pipeline.

Beethoven's *Große Fuge, Op. 133* is a single theme fractured into six
voices that refuse to let go of each other. Personal data does the same
thing: one phone number drags an email address, which drags a name, which
drags a street. GROSSE FUGUE finds the fragments and lets you **mask** them
or bind them to **stable pseudonyms** before anything leaves the room.

This is a *cleansing* tool, not a surveillance one: it never looks anything
up, never compares against other data, and forgets everything after the
pipeline finishes.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
