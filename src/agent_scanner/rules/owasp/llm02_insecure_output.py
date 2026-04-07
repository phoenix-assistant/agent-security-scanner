"""
LLM02: Insecure Output Handling

Detects vulnerabilities where LLM output is used without proper validation
or sanitization, potentially leading to XSS, code injection, or other attacks.

References:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
- CWE-94: Improper Control of Generation of Code
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Dict, Optional, List

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule
from agent_scanner.rules.registry import register_rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@register_rule
class InsecureOutputHandlingRule(Rule):
    """
    LLM02-A: Insecure Output Handling
    
    Detects when LLM output is passed to dangerous sinks without validation.
    """
    
    id = "LLM02-A"
    name = "Insecure Output Handling"
    description = "LLM output used without validation in dangerous context"
    severity = Severity.HIGH
    cwe_id = "CWE-79"
    owasp_id = "LLM02"
    
    # LLM output sources
    LLM_OUTPUT_METHODS = {
        "invoke", "ainvoke",
        "generate", "agenerate",
        "complete", "acomplete",
        "run", "arun",
        "chat", "achat",
        "predict", "apredict",
        "call", "__call__",
    }
    
    # Dangerous sinks for LLM output
    DANGEROUS_SINKS = {
        # Web output (XSS)
        "render_template_string": "XSS via template injection",
        "Markup": "XSS if output contains HTML",
        "innerHTML": "XSS via DOM manipulation",
        "document.write": "XSS via document.write",
        # Code execution
        "exec": "Arbitrary code execution",
        "eval": "Arbitrary code execution",
        "compile": "Code compilation from LLM output",
        # Shell
        "system": "Shell command execution",
        "popen": "Shell command execution",
        "subprocess.run": "Shell command execution",
        "subprocess.call": "Shell command execution",
        # SQL
        "execute": "Potential SQL injection",
        "executemany": "Potential SQL injection",
        # File system
        "open": "File system access",
        "write": "File write",
    }
    
    # Validation functions that make sinks safer
    VALIDATORS = {
        "escape", "sanitize", "clean", "validate",
        "bleach", "html_escape", "quote",
        "strip_tags", "remove_script",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for insecure output handling."""
        findings: list[Finding] = []
        
        # Track LLM output variables
        llm_outputs: Dict[str, int] = {}  # var -> line
        
        for node in ast.walk(parsed_file.tree):
            # Track LLM output assignments
            if isinstance(node, ast.Assign):
                if self._is_llm_output(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            llm_outputs[target.id] = node.lineno
            
            # Check for LLM output flowing to dangerous sinks
            if isinstance(node, ast.Call):
                finding = self._check_dangerous_sink(node, llm_outputs, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _is_llm_output(self, node: ast.AST) -> bool:
        """Check if node represents LLM output."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                return node.func.attr in self.LLM_OUTPUT_METHODS
        return False
    
    def _check_dangerous_sink(
        self,
        node: ast.Call,
        llm_outputs: Dict[str, int],
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check if LLM output flows to a dangerous sink."""
        
        func_name = self._get_full_func_name(node)
        if not func_name:
            return None
        
        # Check if this is a dangerous sink
        danger_desc = None
        for sink, desc in self.DANGEROUS_SINKS.items():
            if sink in func_name:
                danger_desc = desc
                break
        
        if not danger_desc:
            return None
        
        # Check if any argument is LLM output
        for arg in node.args:
            llm_var = self._find_llm_output_var(arg, llm_outputs)
            if llm_var:
                # Check if there's validation
                if not self._has_validation_wrapper(node):
                    return self.create_finding(
                        title=f"LLM output to {func_name} ({danger_desc})",
                        description=(
                            f"Variable '{llm_var}' (LLM output from line {llm_outputs[llm_var]}) "
                            f"flows to {func_name} without validation. "
                            f"Risk: {danger_desc}."
                        ),
                        file_path=parsed_file.path,
                        line=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=(
                            "1. Validate LLM output format before use\n"
                            "2. Sanitize/escape output appropriate to the context\n"
                            "3. Use allowlists for expected output patterns\n"
                            "4. Consider structured output (JSON schema) instead"
                        ),
                    )
        
        return None
    
    def _find_llm_output_var(
        self,
        node: ast.AST,
        llm_outputs: Dict[str, int],
    ) -> Optional[str]:
        """Find LLM output variable in expression."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in llm_outputs:
                return child.id
        return None
    
    def _has_validation_wrapper(self, node: ast.Call) -> bool:
        """Check if the call is wrapped in validation."""
        # Check parent for validation function
        # This is a simplified check - real implementation would need parent tracking
        return False
    
    def _get_full_func_name(self, node: ast.Call) -> Optional[str]:
        """Get full function name including module."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None


@register_rule
class OutputToExecutionRule(Rule):
    """
    LLM02-B: LLM Output to Code Execution
    
    Specifically detects the dangerous pattern of executing code
    generated by an LLM.
    """
    
    id = "LLM02-B"
    name = "LLM Output Execution"
    description = "LLM-generated code is executed without sandboxing"
    severity = Severity.CRITICAL
    cwe_id = "CWE-94"
    owasp_id = "LLM02"
    
    # Code execution functions
    EXEC_FUNCTIONS = {"exec", "eval", "compile"}
    
    # LLM code generation indicators
    CODE_GEN_KEYWORDS = {
        "code", "python", "script", "program",
        "execute", "run", "implementation",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for LLM output being executed."""
        findings: list[Finding] = []
        
        # Look for patterns like: exec(llm.invoke("write code..."))
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                
                if func_name in self.EXEC_FUNCTIONS:
                    # Check if the argument looks like LLM output
                    for arg in node.args:
                        if self._is_llm_code_generation(arg):
                            findings.append(self.create_finding(
                                title="Executing LLM-generated code",
                                description=(
                                    f"Code generated by an LLM is passed directly to {func_name}(). "
                                    "LLMs can generate malicious code, either through prompt "
                                    "injection or inherent unpredictability."
                                ),
                                file_path=parsed_file.path,
                                line=node.lineno,
                                column=node.col_offset,
                                fix_suggestion=(
                                    "1. NEVER execute LLM output directly\n"
                                    "2. Use a sandboxed environment (E2B, Modal, Docker)\n"
                                    "3. Implement code review/AST validation\n"
                                    "4. Use restricted execution (RestrictedPython)\n"
                                    "5. Consider structured tool calls instead of code gen"
                                ),
                            ))
        
        return findings
    
    def _is_llm_code_generation(self, node: ast.AST) -> bool:
        """Check if node appears to be LLM code generation."""
        
        # Direct LLM call
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in {"invoke", "run", "generate", "complete"}:
                    # Check if prompt mentions code
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if any(kw in arg.value.lower() for kw in self.CODE_GEN_KEYWORDS):
                                return True
        
        # Variable that might hold LLM output (heuristic)
        if isinstance(node, ast.Name):
            name_lower = node.id.lower()
            if any(kw in name_lower for kw in {"response", "output", "result", "code", "generated"}):
                return True
        
        return False
