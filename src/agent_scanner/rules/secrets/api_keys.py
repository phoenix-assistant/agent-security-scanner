"""
API Key Detection Rules.

Detects hardcoded API keys for common services.
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, Optional, List, Tuple

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule
from agent_scanner.rules.registry import register_rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@register_rule
class HardcodedAPIKeyRule(Rule):
    """
    SEC-001: Hardcoded API Key Detection
    
    Detects hardcoded API keys for various services.
    """
    
    id = "SEC-001"
    name = "Hardcoded API Key"
    description = "API key appears to be hardcoded in source"
    severity = Severity.CRITICAL
    cwe_id = "CWE-798"
    owasp_id = "A07"
    
    # API key patterns (regex, service name, min_entropy)
    API_KEY_PATTERNS: List[Tuple[str, str, int]] = [
        # OpenAI
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI", 40),
        (r"sk-proj-[a-zA-Z0-9\-_]{40,}", "OpenAI Project", 40),
        
        # Anthropic
        (r"sk-ant-[a-zA-Z0-9\-_]{40,}", "Anthropic", 40),
        
        # Google
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API", 30),
        
        # AWS
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key", 16),
        (r"[0-9a-zA-Z/+]{40}", "AWS Secret Key", 40),
        
        # Azure
        (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "Azure/UUID", 32),
        
        # Stripe
        (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live", 24),
        (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test", 24),
        (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted", 24),
        
        # Twilio
        (r"SK[0-9a-f]{32}", "Twilio", 32),
        
        # SendGrid
        (r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}", "SendGrid", 50),
        
        # Slack
        (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "Slack", 30),
        
        # GitHub
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT", 36),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth", 36),
        (r"ghu_[a-zA-Z0-9]{36}", "GitHub User", 36),
        (r"ghs_[a-zA-Z0-9]{36}", "GitHub Server", 36),
        
        # Hugging Face
        (r"hf_[a-zA-Z0-9]{34}", "HuggingFace", 34),
        
        # Cohere
        (r"[a-zA-Z0-9]{40}", "Generic 40-char", 40),  # Lower priority
        
        # Discord
        (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", "Discord Bot Token", 50),
        
        # npm
        (r"npm_[A-Za-z0-9]{36}", "npm Token", 36),
        
        # PyPI
        (r"pypi-[A-Za-z0-9_]{50,}", "PyPI Token", 50),
    ]
    
    # Variable names that suggest API keys
    KEY_VAR_NAMES = {
        "api_key", "apikey", "api_token",
        "secret_key", "secretkey", "secret",
        "access_key", "accesskey",
        "auth_token", "authtoken",
        "bearer_token", "bearertoken",
        "private_key", "privatekey",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for hardcoded API keys."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            # Check string literals
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                finding = self._check_string_for_key(node, parsed_file)
                if finding:
                    findings.append(finding)
            
            # Check assignments with key-like names
            if isinstance(node, ast.Assign):
                finding = self._check_assignment(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_string_for_key(
        self,
        node: ast.Constant,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check if a string literal looks like an API key."""
        
        value = node.value
        if len(value) < 16:  # Too short to be a key
            return None
        
        for pattern, service, min_len in self.API_KEY_PATTERNS:
            match = re.search(pattern, value)
            if match:
                matched_value = match.group()
                # Mask most of the key
                masked = matched_value[:8] + "..." + matched_value[-4:]
                
                return self.create_finding(
                    title=f"Potential {service} API key in source",
                    description=(
                        f"String matching {service} API key pattern found: {masked}. "
                        "Hardcoded API keys are a critical security risk."
                    ),
                    file_path=parsed_file.path,
                    line=node.lineno,
                    column=node.col_offset,
                    fix_suggestion=(
                        "1. Remove the key from source code immediately\n"
                        "2. Rotate the compromised key\n"
                        "3. Use environment variables: os.environ['API_KEY']\n"
                        "4. Use secrets management (AWS Secrets Manager, Vault)"
                    ),
                )
        
        return None
    
    def _check_assignment(
        self,
        node: ast.Assign,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check assignments to key-like variable names."""
        
        # Get variable name
        var_name = None
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                break
        
        if not var_name:
            return None
        
        # Check if name suggests a key
        is_key_var = any(kv in var_name for kv in self.KEY_VAR_NAMES)
        if not is_key_var:
            return None
        
        # Check if value is a hardcoded string
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            if len(value) >= 16:
                masked = value[:4] + "..." + value[-4:] if len(value) > 12 else "***"
                
                return self.create_finding(
                    title=f"Hardcoded value in key variable '{node.targets[0].id}'",
                    description=(
                        f"Variable '{node.targets[0].id}' (suggesting an API key) "
                        f"is assigned a hardcoded string value: {masked}"
                    ),
                    file_path=parsed_file.path,
                    line=node.lineno,
                    column=node.col_offset,
                    fix_suggestion=(
                        f"Replace with:\n"
                        f"  {node.targets[0].id} = os.environ.get('{node.targets[0].id.upper()}')"
                    ),
                )
        
        return None


@register_rule
class EnvironmentKeyExposureRule(Rule):
    """
    SEC-002: Environment Key Exposure
    
    Detects when environment variables containing keys are logged or exposed.
    """
    
    id = "SEC-002"
    name = "Environment Key Exposure"
    description = "Environment variable with key may be exposed"
    severity = Severity.HIGH
    cwe_id = "CWE-532"
    owasp_id = "A09"
    
    # Environment variable patterns for keys
    KEY_ENV_PATTERNS = {
        "API_KEY", "SECRET", "TOKEN", "PASSWORD",
        "PRIVATE_KEY", "ACCESS_KEY", "AUTH",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for environment key exposure."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                finding = self._check_env_logging(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_env_logging(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check if env vars with keys are being logged."""
        
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        # Check for logging/printing
        is_logging = func_name and func_name.lower() in {
            "print", "log", "info", "debug", "warning", "error",
            "write", "send",
        }
        
        if not is_logging:
            return None
        
        # Check arguments for env var access
        for arg in node.args:
            env_var = self._find_env_access(arg)
            if env_var:
                for pattern in self.KEY_ENV_PATTERNS:
                    if pattern in env_var.upper():
                        return self.create_finding(
                            title=f"Sensitive env var '{env_var}' may be logged",
                            description=(
                                f"Environment variable '{env_var}' (likely containing secrets) "
                                f"is passed to {func_name}(). This could expose the key in logs."
                            ),
                            file_path=parsed_file.path,
                            line=node.lineno,
                            column=node.col_offset,
                            fix_suggestion=(
                                "1. Never log environment variables containing secrets\n"
                                "2. Use masked logging if debug needed\n"
                                "3. Review log destinations and access controls"
                            ),
                        )
        
        return None
    
    def _find_env_access(self, node: ast.AST) -> Optional[str]:
        """Find environment variable access in expression."""
        for child in ast.walk(node):
            if isinstance(child, ast.Subscript):
                if isinstance(child.value, ast.Attribute):
                    if child.value.attr == "environ":
                        if isinstance(child.slice, ast.Constant):
                            return child.slice.value
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in {"get", "getenv"}:
                        if child.args:
                            if isinstance(child.args[0], ast.Constant):
                                return child.args[0].value
        return None
