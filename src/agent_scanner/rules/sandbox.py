"""
ASS-004: Code Execution Without Sandbox

Detects when code execution capabilities (exec, eval, subprocess)
are used without proper sandboxing/isolation.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


class MissingSandboxRule(Rule):
    """
    ASS-004: Detects code execution without sandbox isolation.
    
    AI agents that execute code need sandboxing to prevent:
    - File system damage
    - Network exfiltration  
    - Resource exhaustion
    - Privilege escalation
    
    This rule flags direct use of exec/eval/subprocess without
    evidence of containerization or sandboxing.
    """
    
    id = "ASS-004"
    name = "Code Execution Without Sandbox"
    description = "Exec/eval without container or VM isolation"
    severity = Severity.CRITICAL
    cwe_id = "CWE-94"
    owasp_id = "LLM06"
    
    # Dangerous execution functions
    EXEC_FUNCTIONS = {
        "exec": "Python code execution",
        "eval": "Python expression evaluation", 
        "compile": "Python code compilation",
    }
    
    # Dangerous subprocess patterns
    SUBPROCESS_PATTERNS = {
        "call": "Shell command execution",
        "run": "Shell command execution",
        "Popen": "Process spawning",
        "check_output": "Shell command with output",
        "check_call": "Shell command with exit check",
        "system": "Shell command via os.system",
        "popen": "Shell command via os.popen",
        "spawn": "Process spawning",
    }
    
    # LangChain-specific code execution tools
    LANGCHAIN_EXEC_TOOLS = {
        "PythonREPLTool": "LangChain Python REPL",
        "PythonREPL": "LangChain Python REPL",
        "ShellTool": "LangChain shell execution",
        "BashProcess": "LangChain bash execution",
        "Terminal": "Terminal execution",
    }
    
    # Sandbox indicators - if these are imported/used, likely sandboxed
    SANDBOX_INDICATORS = {
        # Container services
        "e2b", "E2B", "e2b_code_interpreter",
        "modal", "Modal",
        "docker", "Docker", "DockerClient",
        "kubernetes", "k8s",
        "firecracker",
        # Sandbox libraries
        "sandbox", "Sandbox",
        "isolate", "Isolate",
        "seccomp",
        "bubblewrap", "bwrap",
        "firejail",
        "nsjail",
        # Cloud execution
        "lambda", "Lambda",
        "cloud_function", "CloudFunction",
        "fargate", "Fargate",
        # RestrictedPython
        "RestrictedPython", "safe_globals",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for unsandboxed code execution."""
        
        findings: list[Finding] = []
        
        # First, check if there are sandbox indicators in the file
        has_sandbox = self._file_has_sandbox_indicators(parsed_file)
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                finding = self._check_call(node, parsed_file, has_sandbox)
                if finding:
                    findings.append(finding)
            
            # Check for imports of dangerous LangChain tools
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                finding = self._check_import(node, parsed_file, has_sandbox)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _file_has_sandbox_indicators(self, parsed_file: "ParsedFile") -> bool:
        """Check if the file shows evidence of sandboxing."""
        
        # Check imports
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(s.lower() in alias.name.lower() for s in self.SANDBOX_INDICATORS):
                        return True
            
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if any(s.lower() in module.lower() for s in self.SANDBOX_INDICATORS):
                    return True
                for alias in node.names:
                    if any(s.lower() in alias.name.lower() for s in self.SANDBOX_INDICATORS):
                        return True
        
        # Check for sandbox-related variable names or comments
        source = parsed_file.source.lower()
        for indicator in ["sandbox", "container", "docker", "isolated", "e2b", "modal"]:
            if indicator in source:
                return True
        
        return False
    
    def _check_call(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
        has_sandbox: bool,
    ) -> Finding | None:
        """Check if a function call is dangerous code execution."""
        
        func_name = None
        full_name = None
        
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            full_name = func_name
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                full_name = f"{node.func.value.id}.{func_name}"
            else:
                full_name = func_name
        
        if not func_name:
            return None
        
        # Check for direct exec/eval
        if func_name in self.EXEC_FUNCTIONS:
            if has_sandbox:
                # Still flag but lower severity
                return self.create_finding(
                    title=f"{self.EXEC_FUNCTIONS[func_name]} detected",
                    description=(
                        f"Use of {func_name}() detected. Sandbox indicators were found "
                        "in this file, but verify that this specific execution is properly "
                        "isolated. Direct {func_name}() bypasses most Python sandboxes."
                    ),
                    file_path=parsed_file.path,
                    line=node.lineno,
                    column=node.col_offset,
                    fix_suggestion=(
                        "Ensure this code execution runs inside your sandbox. "
                        "Consider using RestrictedPython for additional safety."
                    ),
                    snippet=parsed_file.get_snippet(node.lineno),
                    confidence=0.6,
                )
            else:
                return self.create_finding(
                    title=f"Unsandboxed {self.EXEC_FUNCTIONS[func_name]}",
                    description=(
                        f"Use of {func_name}() without visible sandbox/container isolation. "
                        "If an agent controls the input to this function, arbitrary code "
                        "can be executed on the host system."
                    ),
                    file_path=parsed_file.path,
                    line=node.lineno,
                    column=node.col_offset,
                    fix_suggestion=(
                        "Wrap code execution in a sandbox:\n"
                        "• E2B (e2b.dev) - Cloud sandboxes for AI\n"
                        "• Modal (modal.com) - Serverless containers\n"
                        "• Docker with restricted permissions\n"
                        "• RestrictedPython for limited execution"
                    ),
                    snippet=parsed_file.get_snippet(node.lineno),
                )
        
        # Check for subprocess patterns
        if func_name in self.SUBPROCESS_PATTERNS:
            if has_sandbox:
                return self.create_finding(
                    title=f"Shell execution via {func_name}()",
                    description=(
                        f"{self.SUBPROCESS_PATTERNS[func_name]} via {func_name}(). "
                        "Sandbox indicators found but verify shell access is restricted."
                    ),
                    file_path=parsed_file.path,
                    line=node.lineno,
                    column=node.col_offset,
                    fix_suggestion=(
                        "Ensure shell commands run in an isolated container. "
                        "Consider restricting available commands via allowlist."
                    ),
                    snippet=parsed_file.get_snippet(node.lineno),
                    confidence=0.6,
                )
            else:
                return self.create_finding(
                    title=f"Unsandboxed shell execution via {func_name}()",
                    description=(
                        f"{self.SUBPROCESS_PATTERNS[func_name]} without container isolation. "
                        "Arbitrary commands could be executed on the host."
                    ),
                    file_path=parsed_file.path,
                    line=node.lineno,
                    column=node.col_offset,
                    fix_suggestion=(
                        "Run shell commands in isolated containers. "
                        "Never execute shell commands from untrusted input directly."
                    ),
                    snippet=parsed_file.get_snippet(node.lineno),
                )
        
        # Check for LangChain execution tools
        if func_name in self.LANGCHAIN_EXEC_TOOLS:
            if has_sandbox:
                return None  # OK if sandboxed
            
            return self.create_finding(
                title=f"LangChain code execution tool: {func_name}",
                description=(
                    f"{self.LANGCHAIN_EXEC_TOOLS[func_name]} instantiated without "
                    "visible sandbox. These tools execute arbitrary code and require "
                    "isolation to be safe."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "Use sandboxed alternatives:\n"
                    "• langchain_experimental.tools.PythonAstREPLTool (safer)\n"
                    "• E2B's code interpreter integration\n"
                    "• Custom tool with container execution"
                ),
                snippet=parsed_file.get_snippet(node.lineno),
            )
        
        return None
    
    def _check_import(
        self,
        node: ast.Import | ast.ImportFrom,
        parsed_file: "ParsedFile",
        has_sandbox: bool,
    ) -> Finding | None:
        """Check for imports of dangerous execution tools."""
        
        if has_sandbox:
            return None  # If sandboxed, importing these is probably fine
        
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name in self.LANGCHAIN_EXEC_TOOLS:
                    return self.create_finding(
                        title=f"Import of code execution tool: {alias.name}",
                        description=(
                            f"Importing {alias.name} from {module}. This tool executes "
                            "arbitrary code and no sandbox indicators were found."
                        ),
                        file_path=parsed_file.path,
                        line=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=(
                            "Ensure code execution is sandboxed before using this tool."
                        ),
                        snippet=parsed_file.get_snippet(node.lineno),
                        confidence=0.7,
                    )
        
        return None
