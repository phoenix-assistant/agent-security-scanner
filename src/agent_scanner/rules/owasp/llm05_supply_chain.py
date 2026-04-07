"""
LLM05: Supply Chain Vulnerabilities

Detects vulnerabilities in the LLM supply chain including:
- Vulnerable dependencies
- Untrusted model sources
- Insecure model loading

References:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, Optional

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule
from agent_scanner.rules.registry import register_rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@register_rule
class SupplyChainVulnerabilityRule(Rule):
    """
    LLM05-A: Supply Chain Vulnerability Detection
    
    Detects usage patterns that may indicate vulnerable dependencies
    or insecure supply chain practices.
    """
    
    id = "LLM05-A"
    name = "Supply Chain Vulnerability"
    description = "Potentially vulnerable or untrusted dependency usage"
    severity = Severity.MEDIUM
    cwe_id = "CWE-829"
    owasp_id = "LLM05"
    
    # Dangerous deserialization
    UNSAFE_LOADERS = {
        "pickle.load",
        "pickle.loads",
        "torch.load",  # Without weights_only=True
        "joblib.load",
        "dill.load",
        "cloudpickle.load",
    }
    
    # Model loading without verification
    MODEL_LOADERS = {
        "from_pretrained",
        "load_model",
        "AutoModel",
        "AutoModelForCausalLM",
        "AutoTokenizer",
        "pipeline",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for supply chain vulnerabilities."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                # Check unsafe deserialization
                finding = self._check_unsafe_deserialization(node, parsed_file)
                if finding:
                    findings.append(finding)
                
                # Check torch.load without weights_only
                finding = self._check_torch_load(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_unsafe_deserialization(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check for unsafe pickle/joblib loading."""
        
        func_name = self._get_full_func_name(node)
        if not func_name:
            return None
        
        if func_name in {"pickle.load", "pickle.loads"}:
            return self.create_finding(
                title="Unsafe pickle deserialization",
                description=(
                    f"Using {func_name} to load data. Pickle can execute arbitrary "
                    "code during deserialization. If loading model weights or data "
                    "from untrusted sources, this is a critical vulnerability."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "1. Use safer formats (JSON, safetensors) when possible\n"
                    "2. Only load pickle from fully trusted sources\n"
                    "3. Verify file integrity with checksums/signatures\n"
                    "4. Consider using fickling to scan pickle files"
                ),
            )
        
        if func_name in {"joblib.load", "dill.load", "cloudpickle.load"}:
            return self.create_finding(
                title=f"Unsafe {func_name.split('.')[0]} deserialization",
                description=(
                    f"Using {func_name} which can execute arbitrary code. "
                    "Similar to pickle, this is dangerous with untrusted data."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion="Use safer serialization formats or verify data integrity.",
            )
        
        return None
    
    def _check_torch_load(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check torch.load for weights_only parameter."""
        
        func_name = self._get_full_func_name(node)
        if func_name != "torch.load":
            return None
        
        # Check for weights_only=True
        has_weights_only = False
        for kw in node.keywords:
            if kw.arg == "weights_only":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_weights_only = True
        
        if not has_weights_only:
            return self.create_finding(
                title="torch.load without weights_only=True",
                description=(
                    "torch.load can execute arbitrary code via pickle. "
                    "Always use weights_only=True when loading model weights, "
                    "or use torch.load with map_location and verify the source."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "Use: torch.load(path, weights_only=True)\n"
                    "Or for safetensors: from safetensors.torch import load_file"
                ),
            )
        
        return None
    
    def _get_full_func_name(self, node: ast.Call) -> Optional[str]:
        """Get full function name including module."""
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        if isinstance(node.func, ast.Name):
            return node.func.id
        return None


@register_rule
class UntrustedModelSourceRule(Rule):
    """
    LLM05-B: Untrusted Model Source
    
    Detects models loaded from potentially untrusted sources without
    verification.
    """
    
    id = "LLM05-B"
    name = "Untrusted Model Source"
    description = "Model loaded from potentially untrusted source"
    severity = Severity.MEDIUM
    cwe_id = "CWE-829"
    owasp_id = "LLM05"
    
    # HuggingFace model loading
    HF_LOADERS = {
        "from_pretrained",
        "AutoModel",
        "AutoModelForCausalLM",
        "AutoModelForSeq2SeqLM",
        "AutoTokenizer",
        "pipeline",
    }
    
    # Trusted model prefixes (not exhaustive)
    TRUSTED_PREFIXES = {
        "openai/", "anthropic/", "google/", "meta-llama/",
        "microsoft/", "facebook/", "EleutherAI/",
        "bigscience/", "stabilityai/", "mistralai/",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for untrusted model sources."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                finding = self._check_model_source(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_model_source(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check model loading source."""
        
        func_name = None
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
        
        if func_name not in self.HF_LOADERS:
            return None
        
        # Get the model ID (usually first argument)
        model_id = None
        if node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                model_id = first_arg.value
        
        # Also check repo_id keyword
        for kw in node.keywords:
            if kw.arg in {"repo_id", "pretrained_model_name_or_path", "model"}:
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.str):
                    model_id = kw.value.value
        
        if not model_id:
            return None
        
        # Check if from trusted source
        is_trusted = any(model_id.startswith(prefix) for prefix in self.TRUSTED_PREFIXES)
        
        # Check for trust_remote_code
        has_trust_remote = False
        for kw in node.keywords:
            if kw.arg == "trust_remote_code":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_trust_remote = True
        
        if has_trust_remote:
            return self.create_finding(
                title=f"Model '{model_id}' loaded with trust_remote_code=True",
                description=(
                    f"Loading model '{model_id}' with trust_remote_code=True allows "
                    "arbitrary code execution from the model repository. This is "
                    "dangerous for untrusted models."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "1. Only use trust_remote_code with verified models\n"
                    "2. Review the model's code before enabling\n"
                    "3. Consider using models that don't require remote code"
                ),
            )
        
        if not is_trusted and "/" in model_id:
            return self.create_finding(
                title=f"Model from community source: {model_id}",
                description=(
                    f"Loading model '{model_id}' from HuggingFace Hub. Community models "
                    "may contain vulnerabilities or malicious code. While this model "
                    "doesn't use trust_remote_code, verify its legitimacy."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "1. Check model's download count and community reviews\n"
                    "2. Verify the organization/author is legitimate\n"
                    "3. Scan model files with security tools\n"
                    "4. Consider using official/verified models"
                ),
                confidence=0.5,  # Lower confidence - might be intentional
            )
        
        return None
