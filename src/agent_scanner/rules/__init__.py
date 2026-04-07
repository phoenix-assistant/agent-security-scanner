"""Security rules for agent code analysis."""

from __future__ import annotations

from agent_scanner.rules.base import Rule
from agent_scanner.rules.prompt_injection import PromptInjectionRule
from agent_scanner.rules.tool_validation import (
    ToolOutputValidationRule,
    ToolInputValidationRule,
)
from agent_scanner.rules.sandbox import MissingSandboxRule
from agent_scanner.rules.permissions import OverPermissionedRule

__all__ = [
    "Rule",
    "PromptInjectionRule",
    "ToolOutputValidationRule",
    "ToolInputValidationRule",
    "MissingSandboxRule",
    "OverPermissionedRule",
]
