"""
Agent Security Scanner - Static security analysis for AI agents.

ESLint for LangChain, CrewAI, AutoGPT, and custom AI agents.
Catches prompt injection vectors, unvalidated tool inputs, missing sandboxing,
and over-permissioned access before your agent ships.
"""

from __future__ import annotations

__version__ = "0.1.0"

from agent_scanner.core.scanner import Scanner
from agent_scanner.core.findings import Finding, Severity

__all__ = ["Scanner", "Finding", "Severity", "__version__"]
