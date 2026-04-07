"""
Secrets Detection Rules.

Detect hardcoded secrets, API keys, and credentials in code.
"""

from __future__ import annotations

from agent_scanner.rules.secrets.api_keys import (
    HardcodedAPIKeyRule,
    EnvironmentKeyExposureRule,
)
from agent_scanner.rules.secrets.credentials import (
    HardcodedPasswordRule,
    HardcodedConnectionStringRule,
)

__all__ = [
    "HardcodedAPIKeyRule",
    "EnvironmentKeyExposureRule",
    "HardcodedPasswordRule",
    "HardcodedConnectionStringRule",
]
