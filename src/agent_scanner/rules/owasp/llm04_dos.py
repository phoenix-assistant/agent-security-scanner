"""
LLM04: Model Denial of Service

Detects vulnerabilities that could lead to resource exhaustion or
denial of service through unbounded operations, missing limits, or
expensive recursive patterns.

References:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- CWE-400: Uncontrolled Resource Consumption
- CWE-770: Allocation of Resources Without Limits
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Optional

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule
from agent_scanner.rules.registry import register_rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@register_rule
class ModelDenialOfServiceRule(Rule):
    """
    LLM04-A: Model Denial of Service
    
    Detects missing token limits, timeouts, and rate limiting that
    could enable DoS attacks.
    """
    
    id = "LLM04-A"
    name = "Model Denial of Service Risk"
    description = "LLM usage lacks resource limits (tokens, timeout, rate)"
    severity = Severity.MEDIUM
    cwe_id = "CWE-400"
    owasp_id = "LLM04"
    
    # LLM client instantiation
    LLM_CLIENTS = {
        "ChatOpenAI", "OpenAI",
        "ChatAnthropic", "Anthropic",
        "ChatGoogleGenerativeAI", "GoogleGenerativeAI",
        "ChatVertexAI", "VertexAI",
        "ChatCohere", "Cohere",
        "ChatMistralAI", "MistralAI",
        "ChatOllama", "Ollama",
        "AzureChatOpenAI", "AzureOpenAI",
    }
    
    # Token limit parameters
    TOKEN_LIMIT_PARAMS = {
        "max_tokens", "max_output_tokens",
        "max_new_tokens", "max_length",
        "max_completion_tokens",
    }
    
    # Timeout parameters
    TIMEOUT_PARAMS = {
        "timeout", "request_timeout",
        "connect_timeout", "read_timeout",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for DoS vulnerabilities."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if not func_name:
                    continue
                
                if func_name in self.LLM_CLIENTS:
                    # Check for missing limits
                    issues = self._check_limits(node)
                    if issues:
                        findings.append(self.create_finding(
                            title=f"{func_name} missing resource limits",
                            description=(
                                f"LLM client {func_name} instantiated without: {', '.join(issues)}. "
                                "Without these limits, malicious inputs could cause expensive "
                                "API calls or resource exhaustion."
                            ),
                            file_path=parsed_file.path,
                            line=node.lineno,
                            column=node.col_offset,
                            fix_suggestion=(
                                "Add resource limits:\n"
                                f"  {func_name}(\n"
                                "      max_tokens=4096,  # Limit output length\n"
                                "      timeout=30,       # Prevent hanging\n"
                                "      max_retries=3,    # Limit retry attempts\n"
                                "  )"
                            ),
                            confidence=0.7,
                        ))
        
        return findings
    
    def _check_limits(self, node: ast.Call) -> list[str]:
        """Check which limits are missing."""
        missing = []
        
        kwarg_names = {kw.arg for kw in node.keywords if kw.arg}
        
        # Check for token limits
        if not any(p in kwarg_names for p in self.TOKEN_LIMIT_PARAMS):
            missing.append("token limit")
        
        # Check for timeout
        if not any(p in kwarg_names for p in self.TIMEOUT_PARAMS):
            missing.append("timeout")
        
        return missing
    
    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None


@register_rule
class UnboundedGenerationRule(Rule):
    """
    LLM04-B: Unbounded Generation Loops
    
    Detects while loops or recursive patterns that generate LLM content
    without proper termination conditions.
    """
    
    id = "LLM04-B"
    name = "Unbounded Generation Loop"
    description = "LLM generation in loop without clear termination"
    severity = Severity.HIGH
    cwe_id = "CWE-770"
    owasp_id = "LLM04"
    
    # LLM invocation methods
    LLM_METHODS = {
        "invoke", "ainvoke",
        "generate", "agenerate",
        "complete", "acomplete",
        "run", "arun",
        "chat", "achat",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for unbounded generation patterns."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            # Check while loops
            if isinstance(node, ast.While):
                finding = self._check_while_loop(node, parsed_file)
                if finding:
                    findings.append(finding)
            
            # Check for loops
            if isinstance(node, ast.For):
                finding = self._check_for_loop(node, parsed_file)
                if finding:
                    findings.append(finding)
            
            # Check recursive agent patterns
            if isinstance(node, ast.FunctionDef):
                finding = self._check_recursive_agent(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_while_loop(
        self,
        node: ast.While,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check while loop for unbounded LLM calls."""
        
        has_llm_call = False
        has_max_iterations = False
        
        for child in ast.walk(node):
            # Check for LLM calls
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in self.LLM_METHODS:
                        has_llm_call = True
            
            # Check for iteration counter
            if isinstance(child, ast.Compare):
                for comparator in child.comparators:
                    if isinstance(comparator, ast.Constant):
                        has_max_iterations = True
        
        # Check condition for True literal (while True:)
        is_infinite = isinstance(node.test, ast.Constant) and node.test.value is True
        
        if has_llm_call and (is_infinite or not has_max_iterations):
            return self.create_finding(
                title="LLM call in potentially unbounded while loop",
                description=(
                    "An LLM is called inside a while loop without a clear maximum "
                    "iteration limit. This could lead to runaway API costs or "
                    "denial of service."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "Add explicit iteration limits:\n"
                    "  max_iterations = 10\n"
                    "  for i in range(max_iterations):\n"
                    "      result = llm.invoke(...)\n"
                    "      if done_condition:\n"
                    "          break"
                ),
            )
        
        return None
    
    def _check_for_loop(
        self,
        node: ast.For,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check for loop for expensive unbounded iteration."""
        
        # Check if iterating over something that could be large/unbounded
        iter_suspicious = False
        
        if isinstance(node.iter, ast.Call):
            func_name = None
            if isinstance(node.iter.func, ast.Name):
                func_name = node.iter.func.id
            elif isinstance(node.iter.func, ast.Attribute):
                func_name = node.iter.func.attr
            
            # Generators or queries that could return many items
            if func_name in {"iter", "itertools", "query", "search", "fetch_all"}:
                iter_suspicious = True
        
        if not iter_suspicious:
            return None
        
        # Check for LLM call in body
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in self.LLM_METHODS:
                        return self.create_finding(
                            title="LLM call in potentially large iteration",
                            description=(
                                "An LLM is called for each item in what appears to be "
                                "a potentially large or unbounded collection. This could "
                                "cause excessive API calls."
                            ),
                            file_path=parsed_file.path,
                            line=node.lineno,
                            column=node.col_offset,
                            fix_suggestion=(
                                "1. Limit the collection size before iteration\n"
                                "2. Use batch processing instead of per-item calls\n"
                                "3. Implement rate limiting"
                            ),
                            confidence=0.6,
                        )
        
        return None
    
    def _check_recursive_agent(
        self,
        node: ast.FunctionDef,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check for recursive agent patterns without depth limits."""
        
        func_name = node.name
        has_llm_call = False
        has_self_call = False
        has_depth_check = False
        
        for child in ast.walk(node):
            # Check for LLM call
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in self.LLM_METHODS:
                        has_llm_call = True
                
                # Check for recursive call
                if isinstance(child.func, ast.Name):
                    if child.func.id == func_name:
                        has_self_call = True
            
            # Check for depth parameter
            if isinstance(child, ast.arg):
                if "depth" in child.arg.lower() or "level" in child.arg.lower():
                    has_depth_check = True
        
        if has_llm_call and has_self_call and not has_depth_check:
            return self.create_finding(
                title=f"Recursive agent function '{func_name}' without depth limit",
                description=(
                    f"Function '{func_name}' contains LLM calls and recursive calls "
                    "without visible depth limiting. This could cause infinite recursion "
                    "and excessive API usage."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    f"Add depth limiting:\n"
                    f"  def {func_name}(..., depth=0, max_depth=5):\n"
                    f"      if depth >= max_depth:\n"
                    f"          return fallback_result\n"
                    f"      ...\n"
                    f"      return {func_name}(..., depth=depth+1)"
                ),
            )
        
        return None
