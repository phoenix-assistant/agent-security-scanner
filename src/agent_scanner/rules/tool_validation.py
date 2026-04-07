"""
ASS-002: Unvalidated Tool Output
ASS-003: Missing Input Validation on Custom Tool

Detects when tool outputs are used without validation and when
custom tools don't validate their inputs.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


class ToolOutputValidationRule(Rule):
    """
    ASS-002: Detects when tool output flows to another tool without validation.
    
    In agent architectures, tools often chain together. If one tool's output
    is passed directly to another tool without validation, a compromised or
    malicious tool output can affect downstream tools.
    """
    
    id = "ASS-002"
    name = "Unvalidated Tool Output"
    description = "Tool output passed to another tool without validation"
    severity = Severity.HIGH
    cwe_id = "CWE-20"
    owasp_id = "LLM06"
    
    # Methods that execute tools
    TOOL_METHODS = {
        "run", "arun", "invoke", "ainvoke", 
        "_run", "_arun",
        "execute", "call",
    }
    
    # Validation patterns
    VALIDATION_PATTERNS = {
        "validate", "sanitize", "clean", "check",
        "parse", "schema", "model_validate", "parse_obj",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for unvalidated tool output usage."""
        
        findings: list[Finding] = []
        
        # Track variables that hold tool output
        tool_output_vars: dict[str, int] = {}  # var_name -> line
        
        for node in ast.walk(parsed_file.tree):
            # Track tool output assignments
            if isinstance(node, ast.Assign):
                if self._is_tool_call(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tool_output_vars[target.id] = node.lineno
            
            # Check for tool calls with tool output as input
            if isinstance(node, ast.Call):
                if self._is_tool_call(node):
                    for arg in node.args:
                        unvalidated = self._has_unvalidated_tool_output(
                            arg, tool_output_vars, parsed_file.tree
                        )
                        if unvalidated:
                            findings.append(self.create_finding(
                                title="Tool output passed to another tool without validation",
                                description=(
                                    f"Variable '{unvalidated}' contains output from a tool "
                                    "and is passed directly to another tool. If the first tool "
                                    "returns malicious data, it can compromise the second tool."
                                ),
                                file_path=parsed_file.path,
                                line=node.lineno,
                                column=node.col_offset,
                                fix_suggestion=(
                                    "Validate tool outputs before passing to other tools. "
                                    "Use Pydantic models or JSON schema validation to ensure "
                                    "the output matches expected structure."
                                ),
                                snippet=parsed_file.get_snippet(node.lineno),
                            ))
        
        return findings
    
    def _is_tool_call(self, node: ast.AST) -> bool:
        """Check if a node is a tool invocation."""
        
        if not isinstance(node, ast.Call):
            return False
        
        if isinstance(node.func, ast.Attribute):
            return node.func.attr in self.TOOL_METHODS
        
        return False
    
    def _has_unvalidated_tool_output(
        self,
        node: ast.AST,
        tool_output_vars: dict[str, int],
        tree: ast.AST,
    ) -> str | None:
        """Check if expression contains unvalidated tool output."""
        
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if child.id in tool_output_vars:
                    # Check if there's validation between assignment and use
                    if not self._has_validation_between(
                        tool_output_vars[child.id],
                        child.lineno,
                        child.id,
                        tree,
                    ):
                        return child.id
        
        return None
    
    def _has_validation_between(
        self,
        start_line: int,
        end_line: int,
        var_name: str,
        tree: ast.AST,
    ) -> bool:
        """Check if there's a validation call between two lines for a variable."""
        
        for node in ast.walk(tree):
            if not hasattr(node, 'lineno'):
                continue
            
            if start_line < node.lineno < end_line:
                if isinstance(node, ast.Call):
                    func_name = None
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id.lower()
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr.lower()
                    
                    if func_name:
                        for pattern in self.VALIDATION_PATTERNS:
                            if pattern in func_name:
                                # Check if our variable is an argument
                                for arg in node.args:
                                    if self._contains_var(arg, var_name):
                                        return True
        
        return False
    
    def _contains_var(self, node: ast.AST, var_name: str) -> bool:
        """Check if a node contains a variable reference."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id == var_name:
                return True
        return False


class ToolInputValidationRule(Rule):
    """
    ASS-003: Detects custom tools that don't validate their inputs.
    
    Custom tools should validate inputs to prevent injection attacks
    and ensure they receive expected data types.
    """
    
    id = "ASS-003"
    name = "Missing Input Validation on Custom Tool"
    description = "Custom tool accepts unvalidated input"
    severity = Severity.MEDIUM
    cwe_id = "CWE-20"
    owasp_id = "LLM06"
    
    # Decorators that indicate a LangChain tool
    TOOL_DECORATORS = {"tool", "Tool"}
    
    # Base classes for tools
    TOOL_BASES = {"BaseTool", "Tool", "StructuredTool"}
    
    # Validation indicators
    VALIDATION_INDICATORS = {
        # Pydantic
        "BaseModel", "validator", "field_validator", "model_validator",
        # Type checking  
        "isinstance", "type(",
        # Schema
        "args_schema", "ArgsSchema",
        # General validation
        "validate", "check", "assert",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for tools without input validation."""
        
        findings: list[Finding] = []
        
        # Check functions with @tool decorator
        for func in parsed_file.parser.functions if hasattr(parsed_file, 'parser') else []:
            if any(d in self.TOOL_DECORATORS for d in func.decorators):
                # This is a tool - check if it has validation
                finding = self._check_tool_function(func, parsed_file)
                if finding:
                    findings.append(finding)
        
        # Also walk the AST directly
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                is_tool = False
                for dec in node.decorator_list:
                    dec_name = None
                    if isinstance(dec, ast.Name):
                        dec_name = dec.id
                    elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                        dec_name = dec.func.id
                    
                    if dec_name in self.TOOL_DECORATORS:
                        is_tool = True
                        break
                
                if is_tool:
                    if not self._function_has_validation(node):
                        findings.append(self.create_finding(
                            title=f"Tool '{node.name}' has no input validation",
                            description=(
                                f"The @tool function '{node.name}' does not appear to "
                                "validate its inputs. Tools should validate inputs to "
                                "prevent injection attacks and type confusion."
                            ),
                            file_path=parsed_file.path,
                            line=node.lineno,
                            column=node.col_offset,
                            fix_suggestion=(
                                "Add input validation using Pydantic's args_schema, "
                                "type annotations with runtime checking, or explicit "
                                "validation logic at the start of the function."
                            ),
                            snippet=parsed_file.get_snippet(node.lineno),
                            confidence=0.8,
                        ))
            
            # Check for classes extending BaseTool
            if isinstance(node, ast.ClassDef):
                if any(b in self.TOOL_BASES for b in self._get_base_names(node)):
                    if not self._class_has_args_schema(node):
                        findings.append(self.create_finding(
                            title=f"Tool class '{node.name}' has no args_schema",
                            description=(
                                f"The tool class '{node.name}' extends BaseTool but "
                                "does not define an args_schema. Without schema validation, "
                                "the tool may receive unexpected or malicious inputs."
                            ),
                            file_path=parsed_file.path,
                            line=node.lineno,
                            column=node.col_offset,
                            fix_suggestion=(
                                "Define an args_schema using a Pydantic BaseModel to "
                                "validate tool inputs. Example:\n"
                                "args_schema: Type[BaseModel] = MyToolInput"
                            ),
                            snippet=parsed_file.get_snippet(node.lineno),
                            confidence=0.9,
                        ))
        
        return findings
    
    def _check_tool_function(self, func, parsed_file: "ParsedFile") -> Finding | None:
        """Check a tool function for validation."""
        # Simplified check - look for validation in docstring or type hints
        # More sophisticated analysis would trace the function body
        return None  # Handled by AST walk above
    
    def _function_has_validation(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if a function has validation logic."""
        
        source = ast.unparse(node) if hasattr(ast, 'unparse') else ""
        
        # Check for validation indicators in the function body
        for indicator in self.VALIDATION_INDICATORS:
            if indicator in source:
                return True
        
        # Check for type annotations (basic validation)
        for arg in node.args.args:
            if arg.annotation is not None:
                # Has type annotation - some level of documentation at least
                # Could be stricter here
                pass
        
        # Check function body for validation patterns
        for stmt in node.body:
            if isinstance(stmt, ast.Assert):
                return True
            if isinstance(stmt, ast.If):
                # Check for isinstance or type checks
                if self._is_type_check(stmt.test):
                    return True
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call_name = self._get_call_name(stmt.value)
                if call_name and any(v in call_name.lower() for v in ["validate", "check", "assert"]):
                    return True
        
        return False
    
    def _is_type_check(self, node: ast.AST) -> bool:
        """Check if a node is a type checking expression."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return node.func.id in ("isinstance", "issubclass", "type")
        return False
    
    def _get_call_name(self, node: ast.Call) -> str | None:
        """Get the name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
    
    def _get_base_names(self, node: ast.ClassDef) -> list[str]:
        """Get base class names from a class definition."""
        names = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                names.append(base.id)
            elif isinstance(base, ast.Attribute):
                names.append(base.attr)
        return names
    
    def _class_has_args_schema(self, node: ast.ClassDef) -> bool:
        """Check if a class has an args_schema defined."""
        for item in node.body:
            if isinstance(item, ast.AnnAssign):
                if isinstance(item.target, ast.Name):
                    if item.target.id == "args_schema":
                        return True
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        if target.id == "args_schema":
                            return True
        return False
