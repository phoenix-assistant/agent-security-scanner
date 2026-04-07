"""
OWASP LLM Top 10 Security Rules.

Comprehensive coverage of the OWASP Top 10 for Large Language Model Applications.
https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

from agent_scanner.rules.owasp.llm01_prompt_injection import (
    PromptInjectionDirectRule,
    PromptInjectionIndirectRule,
)
from agent_scanner.rules.owasp.llm02_insecure_output import (
    InsecureOutputHandlingRule,
    OutputToExecutionRule,
)
from agent_scanner.rules.owasp.llm03_training_data import (
    TrainingDataPoisoningRule,
    UnsafeFineTuningRule,
)
from agent_scanner.rules.owasp.llm04_dos import (
    ModelDenialOfServiceRule,
    UnboundedGenerationRule,
)
from agent_scanner.rules.owasp.llm05_supply_chain import (
    SupplyChainVulnerabilityRule,
    UntrustedModelSourceRule,
)
from agent_scanner.rules.owasp.llm06_disclosure import (
    SensitiveInfoDisclosureRule,
    PIIInPromptsRule,
)
from agent_scanner.rules.owasp.llm07_insecure_plugin import (
    InsecurePluginDesignRule,
    PluginPermissionRule,
)
from agent_scanner.rules.owasp.llm08_excessive_agency import (
    ExcessiveAgencyRule,
    UnauthorizedActionsRule,
)
from agent_scanner.rules.owasp.llm09_overreliance import (
    OverrelianceRule,
    MissingHumanInLoopRule,
)
from agent_scanner.rules.owasp.llm10_model_theft import (
    ModelTheftRule,
    ModelExposureRule,
)

__all__ = [
    # LLM01
    "PromptInjectionDirectRule",
    "PromptInjectionIndirectRule",
    # LLM02
    "InsecureOutputHandlingRule",
    "OutputToExecutionRule",
    # LLM03
    "TrainingDataPoisoningRule",
    "UnsafeFineTuningRule",
    # LLM04
    "ModelDenialOfServiceRule",
    "UnboundedGenerationRule",
    # LLM05
    "SupplyChainVulnerabilityRule",
    "UntrustedModelSourceRule",
    # LLM06
    "SensitiveInfoDisclosureRule",
    "PIIInPromptsRule",
    # LLM07
    "InsecurePluginDesignRule",
    "PluginPermissionRule",
    # LLM08
    "ExcessiveAgencyRule",
    "UnauthorizedActionsRule",
    # LLM09
    "OverrelianceRule",
    "MissingHumanInLoopRule",
    # LLM10
    "ModelTheftRule",
    "ModelExposureRule",
]
