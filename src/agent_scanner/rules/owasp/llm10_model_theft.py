"""
LLM10: Model Theft

Detects vulnerabilities that could lead to model theft including:
- Exposed model weights
- Missing authentication on model endpoints
- Model serialization without protection

References:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- CWE-522: Insufficiently Protected Credentials
- CWE-306: Missing Authentication for Critical Function
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
class ModelTheftRule(Rule):
    """
    LLM10-A: Model Theft Risk
    
    Detects patterns that could enable model theft.
    """
    
    id = "LLM10-A"
    name = "Model Theft Risk"
    description = "Model weights or endpoints may be exposed"
    severity = Severity.MEDIUM
    cwe_id = "CWE-522"
    owasp_id = "LLM10"
    
    # Model saving functions
    MODEL_SAVE_FUNCS = {
        "save_pretrained", "save_model",
        "torch.save", "save_weights",
        "export_model", "dump",
        "to_disk", "save",
    }
    
    # Model serving patterns
    SERVING_PATTERNS = {
        "app.route", "router.get", "router.post",
        "FastAPI", "Flask",
        "inference", "predict", "generate",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for model theft vulnerabilities."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            # Check for model saving to accessible locations
            if isinstance(node, ast.Call):
                finding = self._check_model_save(node, parsed_file)
                if finding:
                    findings.append(finding)
            
            # Check for model endpoints without auth
            if isinstance(node, ast.FunctionDef):
                finding = self._check_model_endpoint(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_model_save(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check model save locations."""
        
        func_name = self._get_func_name(node)
        if not func_name:
            return None
        
        is_model_save = any(save in func_name for save in self.MODEL_SAVE_FUNCS)
        if not is_model_save:
            return None
        
        # Check save path
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                path = arg.value.lower()
                # Check for publicly accessible paths
                public_paths = ["/var/www", "/public", "/static", "/tmp", "s3://"]
                if any(pub in path for pub in public_paths):
                    return self.create_finding(
                        title=f"Model saved to potentially accessible path",
                        description=(
                            f"Model saved via {func_name} to '{arg.value}'. "
                            "This path may be publicly accessible, risking model theft."
                        ),
                        file_path=parsed_file.path,
                        line=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=(
                            "1. Save models to protected directories\n"
                            "2. Use access controls on model storage\n"
                            "3. Consider model encryption at rest\n"
                            "4. If using cloud storage, ensure private access"
                        ),
                    )
        
        return None
    
    def _check_model_endpoint(
        self,
        node: ast.FunctionDef,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check model serving endpoints for authentication."""
        
        # Check if this looks like an inference endpoint
        is_inference = any(
            pattern in node.name.lower()
            for pattern in ["predict", "inference", "generate", "embed", "complete"]
        )
        
        if not is_inference:
            return None
        
        # Check decorators for route definitions
        has_route = False
        has_auth = False
        
        for decorator in node.decorator_list:
            dec_str = ast.dump(decorator).lower()
            
            # Check for route decorator
            if any(r in dec_str for r in ["route", "get", "post", "api"]):
                has_route = True
            
            # Check for auth decorator
            if any(a in dec_str for a in ["auth", "login_required", "token", "jwt", "bearer"]):
                has_auth = True
        
        # Also check function body for auth
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if any(a in child.id.lower() for a in ["auth", "token", "api_key", "bearer"]):
                    has_auth = True
                    break
        
        if has_route and not has_auth:
            return self.create_finding(
                title=f"Model endpoint '{node.name}' may lack authentication",
                description=(
                    f"Endpoint '{node.name}' appears to serve model inference "
                    "without visible authentication. Unauthenticated access "
                    "could enable model extraction attacks."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "1. Add authentication to model endpoints\n"
                    "2. Implement rate limiting to prevent extraction\n"
                    "3. Monitor for unusual query patterns\n"
                    "4. Consider output perturbation for protection"
                ),
                confidence=0.6,
            )
        
        return None
    
    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None


@register_rule
class ModelExposureRule(Rule):
    """
    LLM10-B: Model Information Exposure
    
    Detects patterns that expose model metadata or internal details.
    """
    
    id = "LLM10-B"
    name = "Model Information Exposure"
    description = "Model details or architecture exposed"
    severity = Severity.LOW
    cwe_id = "CWE-200"
    owasp_id = "LLM10"
    
    # Model info that shouldn't be exposed
    SENSITIVE_MODEL_INFO = {
        "config", "architecture", "num_parameters",
        "training_args", "hyperparameters",
        "model_path", "checkpoint",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for model information exposure."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            # Check for model info in API responses
            if isinstance(node, ast.Return):
                finding = self._check_return_exposure(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_return_exposure(
        self,
        node: ast.Return,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check if return value exposes model info."""
        
        if node.value is None:
            return None
        
        # Check for dict with model info
        if isinstance(node.value, ast.Dict):
            exposed_keys = []
            for key in node.value.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if key.value.lower() in self.SENSITIVE_MODEL_INFO:
                        exposed_keys.append(key.value)
            
            if exposed_keys:
                return self.create_finding(
                    title="Model information exposed in response",
                    description=(
                        f"Response includes model details: {', '.join(exposed_keys)}. "
                        "Exposing model architecture or training information "
                        "can help attackers craft extraction attacks."
                    ),
                    file_path=parsed_file.path,
                    line=node.lineno,
                    column=node.col_offset,
                    fix_suggestion=(
                        "1. Remove model metadata from API responses\n"
                        "2. Return only necessary output fields\n"
                        "3. Obfuscate model version/architecture details"
                    ),
                    confidence=0.5,
                )
        
        return None
