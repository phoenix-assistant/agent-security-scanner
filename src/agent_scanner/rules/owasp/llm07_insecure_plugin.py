"""
LLM07: Insecure Plugin Design

Detects vulnerabilities in LLM plugin/tool implementations including:
- Missing input validation
- Overly broad permissions
- Lack of authentication
- Unsafe data handling

References:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- CWE-20: Improper Input Validation
- CWE-284: Improper Access Control
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Optional, List, Set

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule
from agent_scanner.rules.registry import register_rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@register_rule
class InsecurePluginDesignRule(Rule):
    """
    LLM07-A: Insecure Plugin Design
    
    Detects tools/plugins that lack proper input validation or
    security controls.
    """
    
    id = "LLM07-A"
    name = "Insecure Plugin Design"
    description = "Tool/plugin lacks security controls"
    severity = Severity.HIGH
    cwe_id = "CWE-20"
    owasp_id = "LLM07"
    
    # Tool decorator patterns
    TOOL_DECORATORS = {
        "tool", "Tool",
        "langchain_tool", "function_tool",
        "register_tool", "ai_function",
    }
    
    # Dangerous operations that need validation
    DANGEROUS_OPS = {
        "execute", "exec", "eval",
        "open", "read", "write",
        "delete", "remove", "unlink",
        "request", "get", "post",
        "query", "sql", "execute_sql",
        "subprocess", "system", "popen",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for insecure plugin design."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.FunctionDef):
                # Check if this is a tool function
                if self._is_tool_function(node):
                    # Check for missing validation
                    issues = self._check_tool_security(node)
                    if issues:
                        findings.append(self.create_finding(
                            title=f"Tool '{node.name}' has security issues",
                            description=(
                                f"Tool function '{node.name}' has the following issues:\n"
                                + "\n".join(f"- {issue}" for issue in issues)
                            ),
                            file_path=parsed_file.path,
                            line=node.lineno,
                            column=node.col_offset,
                            fix_suggestion=(
                                "1. Validate all inputs before use\n"
                                "2. Use allowlists for acceptable values\n"
                                "3. Sanitize inputs for dangerous characters\n"
                                "4. Implement proper error handling\n"
                                "5. Add authentication/authorization checks"
                            ),
                        ))
        
        return findings
    
    def _is_tool_function(self, node: ast.FunctionDef) -> bool:
        """Check if function is decorated as a tool."""
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id in self.TOOL_DECORATORS:
                    return True
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    if decorator.func.id in self.TOOL_DECORATORS:
                        return True
            elif isinstance(decorator, ast.Attribute):
                if decorator.attr in self.TOOL_DECORATORS:
                    return True
        return False
    
    def _check_tool_security(self, node: ast.FunctionDef) -> List[str]:
        """Check tool function for security issues."""
        issues = []
        
        # Get parameter names
        params = {arg.arg for arg in node.args.args}
        
        # Track if parameters are validated
        validated_params: Set[str] = set()
        has_dangerous_op = False
        dangerous_op_line = None
        
        for child in ast.walk(node):
            # Check for validation patterns
            if isinstance(child, ast.If):
                # Look for validation in condition
                for name in ast.walk(child.test):
                    if isinstance(name, ast.Name) and name.id in params:
                        validated_params.add(name.id)
            
            # Check for dangerous operations
            if isinstance(child, ast.Call):
                func_name = self._get_func_name(child)
                if func_name and any(op in func_name.lower() for op in self.DANGEROUS_OPS):
                    has_dangerous_op = True
                    dangerous_op_line = child.lineno
                    
                    # Check if using unvalidated params
                    for arg in child.args:
                        for name in ast.walk(arg):
                            if isinstance(name, ast.Name):
                                if name.id in params and name.id not in validated_params:
                                    issues.append(
                                        f"Parameter '{name.id}' used in {func_name}() "
                                        f"without visible validation"
                                    )
        
        # Check for type hints (basic validation)
        has_type_hints = all(arg.annotation is not None for arg in node.args.args)
        if not has_type_hints and has_dangerous_op:
            issues.append("Tool performs dangerous operations but lacks type hints")
        
        # Check for docstring (needed for LLM to understand proper use)
        if not ast.get_docstring(node):
            issues.append("Tool lacks docstring (LLM won't understand intended use)")
        
        return issues
    
    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None


@register_rule  
class PluginPermissionRule(Rule):
    """
    LLM07-B: Plugin Permission Issues
    
    Detects plugins/tools with overly broad permissions or missing
    access controls.
    """
    
    id = "LLM07-B"
    name = "Plugin Permission Issues"
    description = "Tool has overly broad or missing access controls"
    severity = Severity.MEDIUM
    cwe_id = "CWE-284"
    owasp_id = "LLM07"
    
    # Broad access patterns
    BROAD_ACCESS_PATTERNS = {
        "*": "Wildcard access",
        "all": "All permissions",
        "admin": "Administrative access",
        "root": "Root access",
        "sudo": "Elevated privileges",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for plugin permission issues."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            # Check for broad permission strings
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for pattern, desc in self.BROAD_ACCESS_PATTERNS.items():
                    if pattern in node.value.lower():
                        # Try to determine context
                        findings.append(self.create_finding(
                            title=f"Potential broad permission: {desc}",
                            description=(
                                f"String '{node.value}' suggests broad permissions. "
                                "Tools should follow least privilege principle."
                            ),
                            file_path=parsed_file.path,
                            line=node.lineno,
                            column=node.col_offset,
                            fix_suggestion=(
                                "1. Grant minimum necessary permissions\n"
                                "2. Use specific resource identifiers instead of wildcards\n"
                                "3. Implement per-operation authorization"
                            ),
                            confidence=0.5,
                        ))
                        break
            
            # Check for tools without permission checks
            if isinstance(node, ast.FunctionDef):
                if self._is_tool_function(node):
                    if not self._has_permission_check(node):
                        if self._performs_sensitive_operation(node):
                            findings.append(self.create_finding(
                                title=f"Tool '{node.name}' lacks permission checks",
                                description=(
                                    f"Tool '{node.name}' performs sensitive operations "
                                    "but doesn't appear to check user permissions."
                                ),
                                file_path=parsed_file.path,
                                line=node.lineno,
                                column=node.col_offset,
                                fix_suggestion=(
                                    "Add permission verification:\n"
                                    "  if not user.has_permission('operation'):\n"
                                    "      raise PermissionError('Unauthorized')"
                                ),
                                confidence=0.6,
                            ))
        
        return findings
    
    def _is_tool_function(self, node: ast.FunctionDef) -> bool:
        """Check if function is a tool."""
        tool_decorators = {"tool", "Tool", "function_tool"}
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id in tool_decorators:
                    return True
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    if decorator.func.id in tool_decorators:
                        return True
        return False
    
    def _has_permission_check(self, node: ast.FunctionDef) -> bool:
        """Check if function has permission verification."""
        permission_keywords = {"permission", "authorize", "can_", "has_", "allowed", "access"}
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = None
                if isinstance(child.func, ast.Name):
                    func_name = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    func_name = child.func.attr
                
                if func_name:
                    if any(kw in func_name.lower() for kw in permission_keywords):
                        return True
        
        return False
    
    def _performs_sensitive_operation(self, node: ast.FunctionDef) -> bool:
        """Check if function performs sensitive operations."""
        sensitive_ops = {"delete", "remove", "write", "update", "create", "execute", "send"}
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = None
                if isinstance(child.func, ast.Name):
                    func_name = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    func_name = child.func.attr
                
                if func_name:
                    if any(op in func_name.lower() for op in sensitive_ops):
                        return True
        
        return False
