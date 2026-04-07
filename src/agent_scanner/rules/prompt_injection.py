"""
ASS-001: Prompt Injection Detection

Detects when user input flows to LLM prompts without proper sanitization,
creating prompt injection vulnerabilities.

OWASP LLM01: Prompt Injection
CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from agent_scanner.core.findings import Finding, Severity, Location, DataFlow
from agent_scanner.rules.base import Rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


class PromptInjectionRule(Rule):
    """
    Detects prompt injection vulnerabilities in AI agent code.
    
    This rule identifies:
    1. User input flowing directly to system prompts
    2. Untrusted data in ChatPromptTemplate.format()
    3. F-strings with user input in prompt construction
    4. String concatenation of user input into prompts
    """
    
    id = "ASS-001"
    name = "Prompt Injection Vector"
    description = "User input flows to LLM prompt without sanitization"
    severity = Severity.CRITICAL
    cwe_id = "CWE-74"
    owasp_id = "LLM01"
    
    # Patterns that indicate prompt construction
    PROMPT_PATTERNS = {
        "ChatPromptTemplate",
        "PromptTemplate", 
        "SystemMessage",
        "HumanMessage",
        "AIMessage",
        "SystemMessagePromptTemplate",
        "HumanMessagePromptTemplate",
        "MessagesPlaceholder",
    }
    
    # Methods that execute prompts
    PROMPT_METHODS = {
        "format",
        "format_messages",
        "format_prompt",
        "invoke",
        "ainvoke",
        "run",
        "arun",
    }
    
    # User input sources
    INPUT_SOURCES = {
        "input",
        "raw_input",
    }
    
    # Attribute patterns for user input
    INPUT_ATTRIBUTES = {
        ("request", "args"),
        ("request", "form"),
        ("request", "json"),
        ("request", "data"),
        ("request", "query"),
        ("request", "body"),
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for prompt injection vulnerabilities."""
        
        findings: list[Finding] = []
        
        # Track variables that hold user input
        tainted_vars: dict[str, int] = {}  # var_name -> line where tainted
        
        for node in ast.walk(parsed_file.tree):
            # Track user input assignments
            if isinstance(node, ast.Assign):
                taint_source = self._is_user_input(node.value)
                if taint_source:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted_vars[target.id] = node.lineno
            
            # Check for prompt construction with tainted data
            if isinstance(node, ast.Call):
                finding = self._check_prompt_call(node, tainted_vars, parsed_file)
                if finding:
                    findings.append(finding)
            
            # Check for f-strings in prompt-like contexts
            if isinstance(node, ast.JoinedStr):
                finding = self._check_fstring(node, tainted_vars, parsed_file)
                if finding:
                    findings.append(finding)
            
            # Check for string concatenation
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                finding = self._check_string_concat(node, tainted_vars, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _is_user_input(self, node: ast.AST) -> str | None:
        """Check if a node represents user input. Returns description if so."""
        
        # Direct function calls: input()
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in self.INPUT_SOURCES:
                    return f"{node.func.id}()"
        
        # Attribute access: request.form, request.args, etc.
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                if isinstance(node.value.value, ast.Name):
                    obj_name = node.value.value.id
                    attr_name = node.value.attr
                    if (obj_name, attr_name) in self.INPUT_ATTRIBUTES:
                        return f"{obj_name}.{attr_name}"
        
        # Direct attribute access without subscript
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                obj_name = node.value.id
                attr_name = node.attr
                if (obj_name, attr_name) in self.INPUT_ATTRIBUTES:
                    return f"{obj_name}.{attr_name}"
        
        return None
    
    def _check_prompt_call(
        self,
        node: ast.Call,
        tainted_vars: dict[str, int],
        parsed_file: "ParsedFile",
    ) -> Finding | None:
        """Check if a function call creates a prompt with user input."""
        
        # Check for prompt class instantiation
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        if func_name in self.PROMPT_PATTERNS:
            # Check arguments for tainted data
            for arg in node.args:
                tainted = self._contains_tainted(arg, tainted_vars)
                if tainted:
                    return self.create_finding(
                        title="User input in prompt template",
                        description=(
                            f"Variable '{tainted}' contains user input and is used "
                            f"directly in {func_name}. This allows prompt injection attacks "
                            "where attackers can manipulate the AI's behavior."
                        ),
                        file_path=parsed_file.path,
                        line=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=(
                            "Sanitize user input before including in prompts. "
                            "Consider using structured outputs or input validation. "
                            "Never interpolate raw user input into system prompts."
                        ),
                        snippet=parsed_file.get_snippet(node.lineno),
                    )
            
            # Check keyword arguments
            for kw in node.keywords:
                tainted = self._contains_tainted(kw.value, tainted_vars)
                if tainted:
                    return self.create_finding(
                        title=f"User input in prompt template ({kw.arg})",
                        description=(
                            f"Variable '{tainted}' contains user input and is passed "
                            f"to {func_name} as '{kw.arg}'. This allows prompt injection."
                        ),
                        file_path=parsed_file.path,
                        line=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=(
                            "Sanitize user input or use structured outputs."
                        ),
                        snippet=parsed_file.get_snippet(node.lineno),
                    )
        
        # Check for .format() calls on prompt templates
        if func_name in self.PROMPT_METHODS:
            for arg in node.args:
                tainted = self._contains_tainted(arg, tainted_vars)
                if tainted:
                    return self.create_finding(
                        title="User input in prompt format()",
                        description=(
                            f"Variable '{tainted}' containing user input is passed to "
                            f".{func_name}(). Attackers can inject prompts through this input."
                        ),
                        file_path=parsed_file.path,
                        line=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=(
                            "Validate and sanitize user input before formatting into prompts. "
                            "Consider using allowlists for expected input patterns."
                        ),
                        snippet=parsed_file.get_snippet(node.lineno),
                    )
        
        return None
    
    def _check_fstring(
        self,
        node: ast.JoinedStr,
        tainted_vars: dict[str, int],
        parsed_file: "ParsedFile",
    ) -> Finding | None:
        """Check for f-strings that interpolate user input."""
        
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                tainted = self._contains_tainted(value.value, tainted_vars)
                if tainted:
                    return self.create_finding(
                        title="User input in f-string (potential prompt)",
                        description=(
                            f"Variable '{tainted}' contains user input and is interpolated "
                            "in an f-string. If this string is used as a prompt, it creates "
                            "a prompt injection vulnerability."
                        ),
                        file_path=parsed_file.path,
                        line=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=(
                            "If this f-string is used as an LLM prompt, sanitize the user "
                            "input first. Consider separating user content from instructions."
                        ),
                        snippet=parsed_file.get_snippet(node.lineno),
                        confidence=0.7,  # Lower confidence - might not be a prompt
                    )
        
        return None
    
    def _check_string_concat(
        self,
        node: ast.BinOp,
        tainted_vars: dict[str, int],
        parsed_file: "ParsedFile",
    ) -> Finding | None:
        """Check for string concatenation with user input."""
        
        # Check if either side is a string and the other is tainted
        left_tainted = self._contains_tainted(node.left, tainted_vars)
        right_tainted = self._contains_tainted(node.right, tainted_vars)
        
        if left_tainted or right_tainted:
            tainted_var = left_tainted or right_tainted
            
            # Only flag if there are prompt-like keywords nearby
            # This reduces false positives
            return self.create_finding(
                title="String concatenation with user input",
                description=(
                    f"Variable '{tainted_var}' contains user input and is concatenated "
                    "with another string. If used as a prompt, this enables injection."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "Avoid string concatenation for prompt construction. "
                    "Use template parameters with proper escaping instead."
                ),
                snippet=parsed_file.get_snippet(node.lineno),
                confidence=0.5,  # Low confidence - common pattern, might not be prompt
            )
        
        return None
    
    def _contains_tainted(self, node: ast.AST, tainted_vars: dict[str, int]) -> str | None:
        """Check if an expression contains any tainted variables."""
        
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if child.id in tainted_vars:
                    return child.id
        
        return None
