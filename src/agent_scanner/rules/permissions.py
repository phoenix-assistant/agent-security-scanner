"""
ASS-005: Over-Permissioned Tool Access

Detects when agents are given more tool access than necessary,
violating the principle of least privilege.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


class OverPermissionedRule(Rule):
    """
    ASS-005: Detects over-permissioned tool access in agents.
    
    AI agents should follow the principle of least privilege.
    This rule flags:
    - Agents with many tools (potential over-permissioning)
    - Mixing of high-risk and low-risk tools
    - Agents with code execution + network tools (dangerous combo)
    """
    
    id = "ASS-005"
    name = "Over-Permissioned Tool Access"
    description = "Agent has more tool access than needed"
    severity = Severity.MEDIUM
    cwe_id = "CWE-250"
    owasp_id = "LLM06"
    
    # Threshold for "too many tools"
    MAX_TOOLS_THRESHOLD = 10
    
    # High-risk tools that should be isolated
    HIGH_RISK_TOOLS = {
        # Code execution
        "PythonREPLTool", "PythonREPL", "ShellTool", "BashProcess",
        "exec", "eval", "subprocess",
        # File system
        "FileWriteTool", "WriteFileTool", "file_write",
        "FileDeleteTool", "DeleteFileTool", "file_delete",
        # Network
        "RequestsTool", "requests", "http",
        # Database
        "SQLDatabaseTool", "sql", "database",
    }
    
    # Dangerous tool combinations
    DANGEROUS_COMBOS = [
        # Code execution + Network = exfiltration risk
        ({"PythonREPLTool", "PythonREPL", "exec", "eval"}, 
         {"RequestsTool", "requests", "http", "WebBrowser"},
         "Code execution + Network access enables data exfiltration"),
        
        # Code execution + File system = persistence risk
        ({"PythonREPLTool", "PythonREPL", "exec", "eval"},
         {"FileWriteTool", "WriteFileTool", "file_write"},
         "Code execution + File write enables malware persistence"),
        
        # SQL + Network = data exfiltration
        ({"SQLDatabaseTool", "sql", "database"},
         {"RequestsTool", "requests", "http"},
         "Database access + Network enables data exfiltration"),
    ]
    
    # Agent creation patterns
    AGENT_PATTERNS = {
        "AgentExecutor",
        "create_react_agent",
        "create_openai_functions_agent",
        "create_structured_chat_agent",
        "create_tool_calling_agent",
        "initialize_agent",
        "Agent",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for over-permissioned tool access."""
        
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                # Check for agent creation
                func_name = self._get_func_name(node)
                if func_name in self.AGENT_PATTERNS:
                    agent_findings = self._check_agent_tools(node, parsed_file)
                    findings.extend(agent_findings)
        
        return findings
    
    def _get_func_name(self, node: ast.Call) -> str | None:
        """Get the function name from a call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
    
    def _check_agent_tools(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> list[Finding]:
        """Check the tools passed to an agent for over-permissioning."""
        
        findings: list[Finding] = []
        tools: list[str] = []
        tools_node: ast.AST | None = None
        
        # Find the tools argument
        for kw in node.keywords:
            if kw.arg == "tools":
                tools_node = kw.value
                tools = self._extract_tool_names(kw.value)
                break
        
        # Also check positional arguments (some APIs take tools as positional)
        if not tools and len(node.args) >= 2:
            tools_node = node.args[1]  # Often the second arg is tools
            tools = self._extract_tool_names(node.args[1])
        
        if not tools:
            return findings
        
        # Check for too many tools
        if len(tools) > self.MAX_TOOLS_THRESHOLD:
            findings.append(self.create_finding(
                title=f"Agent with {len(tools)} tools (consider reducing)",
                description=(
                    f"This agent has access to {len(tools)} tools, which exceeds "
                    f"the recommended maximum of {self.MAX_TOOLS_THRESHOLD}. "
                    "More tools increase attack surface and make the agent harder "
                    "to reason about security-wise."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "Apply principle of least privilege:\n"
                    "• Split into multiple specialized agents\n"
                    "• Only include tools needed for the specific task\n"
                    "• Consider dynamic tool loading based on context"
                ),
                snippet=parsed_file.get_snippet(node.lineno),
                confidence=0.7,
            ))
        
        # Check for high-risk tools
        high_risk_present = [t for t in tools if t in self.HIGH_RISK_TOOLS]
        if high_risk_present:
            findings.append(self.create_finding(
                title=f"Agent with high-risk tools: {', '.join(high_risk_present[:3])}",
                description=(
                    f"This agent has access to high-risk tools: {', '.join(high_risk_present)}. "
                    "These tools can cause significant damage if misused. "
                    "Ensure proper guardrails and monitoring are in place."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "For agents with high-risk tools:\n"
                    "• Add human-in-the-loop for sensitive operations\n"
                    "• Implement rate limiting\n"
                    "• Log all tool invocations\n"
                    "• Consider sandboxing"
                ),
                snippet=parsed_file.get_snippet(node.lineno),
                confidence=0.8,
            ))
        
        # Check for dangerous combinations
        tools_set = set(tools)
        for group_a, group_b, message in self.DANGEROUS_COMBOS:
            has_a = bool(tools_set & group_a)
            has_b = bool(tools_set & group_b)
            
            if has_a and has_b:
                matched_a = list(tools_set & group_a)
                matched_b = list(tools_set & group_b)
                findings.append(self.create_finding(
                    title="Dangerous tool combination",
                    description=(
                        f"{message}. Found: {matched_a} + {matched_b}. "
                        "This combination significantly increases risk."
                    ),
                    file_path=parsed_file.path,
                    line=node.lineno,
                    column=node.col_offset,
                    fix_suggestion=(
                        "Separate these tools into different agents with different "
                        "permission levels. Use agent orchestration to coordinate "
                        "without giving all tools to a single agent."
                    ),
                    snippet=parsed_file.get_snippet(node.lineno),
                ))
        
        return findings
    
    def _extract_tool_names(self, node: ast.AST) -> list[str]:
        """Extract tool names from a tools argument."""
        
        tools: list[str] = []
        
        # Handle list literal: tools=[tool1, tool2]
        if isinstance(node, ast.List):
            for elt in node.elts:
                name = self._get_tool_name(elt)
                if name:
                    tools.append(name)
        
        # Handle variable reference: tools=my_tools
        elif isinstance(node, ast.Name):
            # Can't statically resolve, but we can note the variable
            tools.append(f"<{node.id}>")
        
        # Handle function call: tools=get_tools()
        elif isinstance(node, ast.Call):
            func_name = self._get_func_name(node)
            tools.append(f"<{func_name}()>")
        
        return tools
    
    def _get_tool_name(self, node: ast.AST) -> str | None:
        """Get the name of a single tool from an expression."""
        
        # Variable: my_tool
        if isinstance(node, ast.Name):
            return node.id
        
        # Instantiation: MyTool()
        if isinstance(node, ast.Call):
            return self._get_func_name(node)
        
        # Attribute: module.MyTool
        if isinstance(node, ast.Attribute):
            return node.attr
        
        return None
