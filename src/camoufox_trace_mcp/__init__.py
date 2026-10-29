"""Camoufox native API trace analysis without browser or MCP dependencies."""

from .analysis import compare_captures, filter_events, summarize
from .reader import Capture, read_capture

__all__ = ["Capture", "read_capture", "summarize", "filter_events", "compare_captures"]
__version__ = "0.1.0"

