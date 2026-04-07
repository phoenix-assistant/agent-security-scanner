"""
LLM08: Excessive Agency

Detects when LLM-based systems are granted too much autonomy or
capability without proper guardrails, including:
- Unrestricted tool access
- Missing human-in-the-loop for critical operations
- Autonomous decision making for sensitive actions

References:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- CWE-250: Execution with Unnecessary Privileges
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Optional, List

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule
from agent_scanner.rules.registry import register_rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@register_rule
class ExcessiveAgencyRule(Rule):
    """
    LLM08-A: Excessive Agency
    
    Detects agents with unrestricted capabilities or missing guardrails.
    """
    
    id = "LLM08-A"
    name = "Excessive Agency"
    description = "Agent has unrestricted or excessive capabilities"
    severity = Severity.HIGH
    cwe_id = "CWE-250"
    owasp_id = "LLM08"
    
    # Agent creation patterns
    AGENT_CREATORS = {
        "Agent", "AgentExecutor",
        "create_agent", "initialize_agent",
        "create_react_agent", "create_openai_functions_agent",
        "create_tool_calling_agent",
        "CrewAI", "Crew",
        "AssistantAgent", "UserProxyAgent",  # AutoGen
    }
    
    # Dangerous tools that need restrictions
    DANGEROUS_TOOLS = {
        "shell", "bash", "terminal",
        "python_repl", "python",
        "file_system", "file_management",
        "code_execution", "exec",
        "system", "subprocess",
        "sql", "database",
        "email", "send_email",
        "api", "http", "requests",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for excessive agency."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                # Check agent creation
                finding = self._check_agent_creation(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_agent_creation(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check agent creation for excessive capabilities."""
        
        func_name = self._get_func_name(node)
        if not func_name or func_name not in self.AGENT_CREATORS:
            return None
        
        issues = []
        
        # Check for tools argument
        tools_arg = None
        for kw in node.keywords:
            if kw.arg == "tools":
                tools_arg = kw.value
                break
        
        if tools_arg is None:
            for i, arg in enumerate(node.args):
                if isinstance(arg, ast.List):
                    tools_arg = arg
                    break
        
        if tools_arg:
            dangerous_tools = self._find_dangerous_tools(tools_arg)
            if dangerous_tools:
                issues.append(
                    f"Has dangerous tools: {', '.join(dangerous_tools)}"
                )
        
        # Check for missing constraints
        has_max_iterations = False
        has_memory_limit = False
        has_tool_filter = False
        
        for kw in node.keywords:
            if kw.arg in {"max_iterations", "max_execution_time", "max_steps"}:
                has_max_iterations = True
            if kw.arg in {"max_tokens", "memory_limit"}:
                has_memory_limit = True
            if kw.arg in {"allowed_tools", "tool_filter", "tool_choice"}:
                has_tool_filter = True
        
        if not has_max_iterations:
            issues.append("No iteration limit (max_iterations)")
        
        # Check for verbose mode in production
        for kw in node.keywords:
            if kw.arg == "verbose":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    issues.append("Verbose mode enabled (may leak info)")
        
        if issues:
            return self.create_finding(
                title=f"Agent '{func_name}' may have excessive agency",
                description=(
                    f"Agent created with {func_name} has potential agency issues:\n"
                    + "\n".join(f"- {issue}" for issue in issues)
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "1. Limit available tools to minimum needed\n"
                    "2. Add max_iterations to prevent runaway execution\n"
                    "3. Implement approval for sensitive operations\n"
                    "4. Use tool filtering to restrict capabilities\n"
                    "5. Disable verbose mode in production"
                ),
            )
        
        return None
    
    def _find_dangerous_tools(self, node: ast.AST) -> List[str]:
        """Find dangerous tools in a tools list."""
        dangerous = []
        
        for child in ast.walk(node):
            # Check tool names
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                tool_lower = child.value.lower()
                for danger in self.DANGEROUS_TOOLS:
                    if danger in tool_lower:
                        dangerous.append(child.value)
                        break
            
            # Check tool variable names
            if isinstance(child, ast.Name):
                name_lower = child.id.lower()
                for danger in self.DANGEROUS_TOOLS:
                    if danger in name_lower:
                        dangerous.append(child.id)
                        break
        
        return list(set(dangerous))
    
    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None


@register_rule
class UnauthorizedActionsRule(Rule):
    """
    LLM08-B: Unauthorized Actions
    
    Detects tools that perform sensitive actions without confirmation.
    """
    
    id = "LLM08-B"
    name = "Unauthorized Actions"
    description = "Sensitive actions without user confirmation"
    severity = Severity.MEDIUM
    cwe_id = "CWE-862"
    owasp_id = "LLM08"
    
    # Actions that should require confirmation
    SENSITIVE_ACTIONS = {
        # Financial
        "transfer", "payment", "purchase", "buy", "sell", "trade",
        # Data
        "delete", "remove", "purge", "drop", "truncate",
        # Communication
        "send_email", "send_message", "post", "publish",
        # System
        "shutdown", "restart", "deploy", "migrate",
        # Account
        "create_user", "delete_user", "change_password", "revoke",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for unauthorized sensitive actions."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.FunctionDef):
                # Check if this is a tool with sensitive action
                if self._is_tool(node):
                    if self._is_sensitive_action(node.name):
                        if not self._has_confirmation(node):
                            findings.append(self.create_finding(
                                title=f"Sensitive tool '{node.name}' lacks confirmation",
                                description=(
                                    f"Tool '{node.name}' appears to perform a sensitive action "
                                    "but doesn't require user confirmation. This violates "
                                    "the principle of human-in-the-loop for important decisions."
                                ),
                                file_path=parsed_file.path,
                                line=node.lineno,
                                column=node.col_offset,
                                fix_suggestion=(
                                    "Add confirmation step:\n"
                                    f"  def {node.name}(..., confirm: bool = False):\n"
                                    "      if not confirm:\n"
                                    "          return 'Please confirm this action'\n"
                                    "      # proceed with action"
                                ),
                            ))
        
        return findings
    
    def _is_tool(self, node: ast.FunctionDef) -> bool:
        """Check if function is decorated as a tool."""
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id.lower() in {"tool", "function_tool"}:
                    return True
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    if decorator.func.id.lower() in {"tool", "function_tool"}:
                        return True
        return False
    
    def _is_sensitive_action(self, name: str) -> bool:
        """Check if function name indicates sensitive action."""
        name_lower = name.lower()
        return any(action in name_lower for action in self.SENSITIVE_ACTIONS)
    
    def _has_confirmation(self, node: ast.FunctionDef) -> bool:
        """Check if function has confirmation mechanism."""
        # Check for confirm parameter
        for arg in node.args.args:
            if "confirm" in arg.arg.lower() or "approve" in arg.arg.lower():
                return True
        
        # Check for confirmation in body
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if "confirm" in child.id.lower() or "approve" in child.id.lower():
                    return True
        
        return False
