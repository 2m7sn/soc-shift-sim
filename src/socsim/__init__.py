"""SOC Shift Simulator: an incident-investigation training range in a box.

All telemetry is synthetic. Nothing here executes any attack.
"""
from .generator import generate
from .query import run as run_query
from .grading import grade, parse_report
from .report import build_html

__all__ = ["generate", "run_query", "grade", "parse_report", "build_html"]
__version__ = "0.1.0"
