"""
LLM06: Sensitive Information Disclosure

Detects vulnerabilities where sensitive information may be exposed through:
- PII in prompts or logs
- Secrets in training data
- Model memorization exposure

References:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- CWE-200: Exposure of Sensitive Information
- CWE-532: Insertion of Sensitive Information into Log File
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, Optional, List

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule
from agent_scanner.rules.registry import register_rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@register_rule
class SensitiveInfoDisclosureRule(Rule):
    """
    LLM06-A: Sensitive Information Disclosure
    
    Detects patterns that may expose sensitive information through
    LLM interactions.
    """
    
    id = "LLM06-A"
    name = "Sensitive Information Disclosure"
    description = "Sensitive data may be exposed through LLM"
    severity = Severity.HIGH
    cwe_id = "CWE-200"
    owasp_id = "LLM06"
    
    # Logging functions
    LOGGING_FUNCTIONS = {
        "print", "logging.info", "logging.debug",
        "logging.warning", "logging.error",
        "logger.info", "logger.debug",
        "logger.warning", "logger.error",
        "log", "console.log",
    }
    
    # Variables that might contain sensitive data
    SENSITIVE_VAR_PATTERNS = {
        r"password", r"passwd", r"secret",
        r"api_key", r"apikey", r"api_secret",
        r"token", r"auth", r"credential",
        r"private_key", r"privatekey",
        r"ssn", r"social_security",
        r"credit_card", r"card_number",
        r"bank_account", r"routing",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for sensitive information disclosure."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            # Check logging of LLM prompts/responses
            if isinstance(node, ast.Call):
                finding = self._check_prompt_logging(node, parsed_file)
                if finding:
                    findings.append(finding)
                
                finding = self._check_sensitive_in_prompt(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_prompt_logging(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check if prompts or responses are being logged."""
        
        func_name = self._get_func_name(node)
        if not func_name:
            return None
        
        is_logging = any(log in func_name.lower() for log in ["print", "log", "debug", "info"])
        if not is_logging:
            return None
        
        # Check if logging something that looks like a prompt/response
        for arg in node.args:
            if isinstance(arg, ast.Name):
                name_lower = arg.id.lower()
                if any(kw in name_lower for kw in ["prompt", "response", "message", "content", "output"]):
                    return self.create_finding(
                        title=f"Logging LLM prompt/response ({arg.id})",
                        description=(
                            f"Variable '{arg.id}' is being logged. LLM prompts and responses "
                            "may contain sensitive user data, PII, or confidential information. "
                            "Logs are often stored insecurely or accessed by many people."
                        ),
                        file_path=parsed_file.path,
                        line=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=(
                            "1. Avoid logging full prompts/responses in production\n"
                            "2. If logging is needed, sanitize/redact sensitive data\n"
                            "3. Use structured logging with PII filtering\n"
                            "4. Ensure logs are encrypted and access-controlled"
                        ),
                        confidence=0.7,
                    )
        
        return None
    
    def _check_sensitive_in_prompt(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check if sensitive variables are included in prompts."""
        
        func_name = self._get_func_name(node)
        if not func_name:
            return None
        
        # Prompt construction patterns
        prompt_patterns = {
            "ChatPromptTemplate", "PromptTemplate",
            "SystemMessage", "HumanMessage",
            "format", "format_messages",
        }
        
        if func_name not in prompt_patterns:
            return None
        
        # Check arguments for sensitive variable names
        sensitive_vars = []
        for arg in node.args:
            for child in ast.walk(arg):
                if isinstance(child, ast.Name):
                    name_lower = child.id.lower()
                    for pattern in self.SENSITIVE_VAR_PATTERNS:
                        if re.search(pattern, name_lower):
                            sensitive_vars.append(child.id)
        
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name):
                name_lower = kw.value.id.lower()
                for pattern in self.SENSITIVE_VAR_PATTERNS:
                    if re.search(pattern, name_lower):
                        sensitive_vars.append(kw.value.id)
        
        if sensitive_vars:
            return self.create_finding(
                title="Sensitive data in LLM prompt",
                description=(
                    f"Variables with sensitive names ({', '.join(set(sensitive_vars))}) "
                    "are included in LLM prompts. This data may be:\n"
                    "- Logged by the LLM provider\n"
                    "- Used in model training\n"
                    "- Exposed through prompt injection attacks"
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "1. Never include passwords/secrets in prompts\n"
                    "2. Redact PII before sending to LLM\n"
                    "3. Use data masking/tokenization\n"
                    "4. Consider on-premise LLM for sensitive data"
                ),
            )
        
        return None
    
    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None


@register_rule
class PIIInPromptsRule(Rule):
    """
    LLM06-B: PII Detection in Prompts
    
    Detects patterns that may include personally identifiable information
    in LLM prompts.
    """
    
    id = "LLM06-B"
    name = "PII in Prompts"
    description = "Potential PII included in LLM prompts"
    severity = Severity.MEDIUM
    cwe_id = "CWE-359"
    owasp_id = "LLM06"
    
    # PII field names
    PII_FIELDS = {
        "name", "full_name", "first_name", "last_name",
        "email", "email_address",
        "phone", "phone_number", "mobile",
        "address", "street", "city", "zip", "postal",
        "ssn", "social_security", "national_id",
        "dob", "date_of_birth", "birthday",
        "driver_license", "passport",
        "ip_address", "user_agent",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for PII in prompts."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                finding = self._check_pii_in_prompt(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_pii_in_prompt(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check for PII being sent to LLM."""
        
        func_name = None
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
        
        # LLM invocation methods
        llm_methods = {"invoke", "ainvoke", "run", "arun", "generate", "complete"}
        if func_name not in llm_methods:
            return None
        
        # Check for PII in arguments
        pii_found = []
        for arg in node.args:
            pii_found.extend(self._find_pii_refs(arg))
        
        for kw in node.keywords:
            pii_found.extend(self._find_pii_refs(kw.value))
        
        if pii_found:
            return self.create_finding(
                title="PII potentially sent to LLM",
                description=(
                    f"Variables that may contain PII ({', '.join(set(pii_found))}) "
                    "appear to flow into an LLM call. Consider:\n"
                    "- Is this data necessary for the task?\n"
                    "- Does the LLM provider's DPA allow this?\n"
                    "- Will users be informed their data is processed by AI?"
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "1. Minimize PII sent to LLMs (data minimization)\n"
                    "2. Anonymize/pseudonymize data before sending\n"
                    "3. Get explicit user consent for AI processing\n"
                    "4. Review LLM provider's data handling policies"
                ),
                confidence=0.6,
            )
        
        return None
    
    def _find_pii_refs(self, node: ast.AST) -> List[str]:
        """Find references to PII fields in expression."""
        found = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if child.id.lower() in self.PII_FIELDS:
                    found.append(child.id)
            if isinstance(child, ast.Subscript):
                if isinstance(child.slice, ast.Constant):
                    if isinstance(child.slice.value, str):
                        if child.slice.value.lower() in self.PII_FIELDS:
                            found.append(child.slice.value)
        return found
