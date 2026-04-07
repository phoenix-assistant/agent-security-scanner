"""
LLM01: Prompt Injection

Detects vulnerabilities where attacker-controlled input can manipulate
LLM behavior through crafted prompts.

Two main categories:
1. Direct Injection - User input directly manipulates the prompt
2. Indirect Injection - External data sources contain malicious prompts

References:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- CWE-74: Improper Neutralization of Special Elements
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, Set, Dict, List, Optional

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule
from agent_scanner.rules.registry import register_rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@register_rule
class PromptInjectionDirectRule(Rule):
    """
    LLM01-A: Direct Prompt Injection
    
    Detects when user input flows directly into LLM prompts without
    proper sanitization or separation.
    """
    
    id = "LLM01-A"
    name = "Direct Prompt Injection"
    description = "User input directly manipulates LLM prompt content"
    severity = Severity.CRITICAL
    cwe_id = "CWE-74"
    owasp_id = "LLM01"
    
    # User input sources
    INPUT_SOURCES = {
        "input", "raw_input",  # Built-in
    }
    
    # Web framework input patterns
    WEB_INPUT_PATTERNS = {
        ("request", "args"),
        ("request", "form"),
        ("request", "json"),
        ("request", "data"),
        ("request", "query_params"),
        ("request", "body"),
        ("request", "GET"),
        ("request", "POST"),
        ("event", "body"),  # AWS Lambda
        ("context", "params"),  # Various frameworks
    }
    
    # Prompt construction patterns
    PROMPT_CLASSES = {
        "ChatPromptTemplate",
        "PromptTemplate",
        "SystemMessage",
        "HumanMessage",
        "AIMessage",
        "SystemMessagePromptTemplate",
        "HumanMessagePromptTemplate",
        "FewShotPromptTemplate",
        "PipelinePromptTemplate",
    }
    
    # Methods that format/execute prompts
    PROMPT_METHODS = {
        "format", "format_messages", "format_prompt",
        "invoke", "ainvoke", "run", "arun",
        "generate", "agenerate",
        "complete", "acomplete",
        "chat", "achat",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for direct prompt injection vulnerabilities."""
        findings: list[Finding] = []
        
        # Track tainted variables
        tainted: Dict[str, tuple[int, str]] = {}  # var -> (line, source_desc)
        
        for node in ast.walk(parsed_file.tree):
            # Track user input assignments
            if isinstance(node, ast.Assign):
                source_info = self._is_user_input(node.value)
                if source_info:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted[target.id] = (node.lineno, source_info)
            
            # Check for prompt construction with tainted data
            if isinstance(node, ast.Call):
                finding = self._check_prompt_call(node, tainted, parsed_file)
                if finding:
                    findings.append(finding)
            
            # Check f-strings that might be prompts
            if isinstance(node, ast.JoinedStr):
                finding = self._check_fstring_prompt(node, tainted, parsed_file)
                if finding:
                    findings.append(finding)
            
            # Check string formatting
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                finding = self._check_percent_format(node, tainted, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _is_user_input(self, node: ast.AST) -> Optional[str]:
        """Check if node represents user input. Returns description if so."""
        
        # Direct function calls
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in self.INPUT_SOURCES:
                    return f"{node.func.id}()"
        
        # Web framework patterns
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                if isinstance(node.value.value, ast.Name):
                    key = (node.value.value.id, node.value.attr)
                    if key in self.WEB_INPUT_PATTERNS:
                        return f"{key[0]}.{key[1]}"
        
        # Attribute access
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                key = (node.value.id, node.attr)
                if key in self.WEB_INPUT_PATTERNS:
                    return f"{key[0]}.{key[1]}"
        
        return None
    
    def _check_prompt_call(
        self,
        node: ast.Call,
        tainted: Dict[str, tuple[int, str]],
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check if a prompt construction uses tainted data."""
        
        func_name = self._get_func_name(node)
        if not func_name:
            return None
        
        # Check prompt class instantiation
        if func_name in self.PROMPT_CLASSES:
            for arg in node.args:
                var = self._find_tainted_var(arg, tainted)
                if var:
                    line, source = tainted[var]
                    return self._create_finding(
                        f"User input from {source} in {func_name}",
                        f"Variable '{var}' (tainted at line {line} from {source}) "
                        f"flows into {func_name}. Attackers can manipulate LLM behavior "
                        "by injecting malicious instructions.",
                        parsed_file,
                        node.lineno,
                        node.col_offset,
                    )
            
            for kw in node.keywords:
                var = self._find_tainted_var(kw.value, tainted)
                if var:
                    line, source = tainted[var]
                    return self._create_finding(
                        f"User input in {func_name}.{kw.arg}",
                        f"Variable '{var}' flows into prompt parameter '{kw.arg}'.",
                        parsed_file,
                        node.lineno,
                        node.col_offset,
                    )
        
        # Check prompt methods
        if func_name in self.PROMPT_METHODS:
            for arg in node.args:
                var = self._find_tainted_var(arg, tainted)
                if var:
                    return self._create_finding(
                        f"User input in .{func_name}() call",
                        f"Tainted variable '{var}' passed to .{func_name}(). "
                        "This can enable prompt injection attacks.",
                        parsed_file,
                        node.lineno,
                        node.col_offset,
                    )
        
        return None
    
    def _check_fstring_prompt(
        self,
        node: ast.JoinedStr,
        tainted: Dict[str, tuple[int, str]],
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check for f-strings with tainted data that might be prompts."""
        
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                var = self._find_tainted_var(value.value, tainted)
                if var:
                    return self.create_finding(
                        title="Potential prompt injection via f-string",
                        description=(
                            f"Tainted variable '{var}' interpolated in f-string. "
                            "If used as an LLM prompt, this enables injection attacks."
                        ),
                        file_path=parsed_file.path,
                        line=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=(
                            "Separate user input from system instructions. "
                            "Use structured prompts with clear boundaries."
                        ),
                        confidence=0.7,  # Lower - might not be a prompt
                    )
        
        return None
    
    def _check_percent_format(
        self,
        node: ast.BinOp,
        tainted: Dict[str, tuple[int, str]],
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check % string formatting with tainted data."""
        
        var = self._find_tainted_var(node.right, tainted)
        if var:
            return self.create_finding(
                title="Potential prompt injection via % formatting",
                description=(
                    f"Tainted variable '{var}' used in string formatting. "
                    "If the result is used as a prompt, this enables injection."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion="Avoid % formatting for prompts. Use template parameters.",
                confidence=0.6,
            )
        
        return None
    
    def _find_tainted_var(
        self,
        node: ast.AST,
        tainted: Dict[str, tuple[int, str]],
    ) -> Optional[str]:
        """Find a tainted variable in an expression."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tainted:
                return child.id
        return None
    
    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
    
    def _create_finding(
        self,
        title: str,
        description: str,
        parsed_file: "ParsedFile",
        line: int,
        column: int,
    ) -> Finding:
        return self.create_finding(
            title=title,
            description=description,
            file_path=parsed_file.path,
            line=line,
            column=column,
            fix_suggestion=(
                "1. Never interpolate user input into system prompts\n"
                "2. Use separate 'user' message role for user content\n"
                "3. Implement input validation and sanitization\n"
                "4. Consider output-based defenses (content filtering)"
            ),
        )


@register_rule
class PromptInjectionIndirectRule(Rule):
    """
    LLM01-B: Indirect Prompt Injection
    
    Detects when external data sources (web pages, documents, APIs)
    flow into prompts without sanitization.
    """
    
    id = "LLM01-B"
    name = "Indirect Prompt Injection"
    description = "External data sources may contain malicious prompts"
    severity = Severity.HIGH
    cwe_id = "CWE-74"
    owasp_id = "LLM01"
    
    # External data sources
    EXTERNAL_SOURCES = {
        # HTTP
        "get", "post", "put", "patch", "delete",
        # File reading
        "read", "readline", "readlines", "read_text",
        # Web scraping
        "scrape", "fetch", "crawl", "extract",
        # Document loading
        "load", "load_documents", "load_file",
        # Database
        "fetchone", "fetchall", "fetchmany", "execute",
    }
    
    # LangChain document loaders
    DOCUMENT_LOADERS = {
        "WebBaseLoader",
        "UnstructuredURLLoader",
        "PyPDFLoader",
        "TextLoader",
        "CSVLoader",
        "JSONLoader",
        "DirectoryLoader",
        "S3FileLoader",
        "AzureBlobStorageFileLoader",
        "GoogleDriveLoader",
        "NotionDBLoader",
        "WikipediaLoader",
        "ArxivLoader",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for indirect prompt injection vulnerabilities."""
        findings: list[Finding] = []
        
        # Track external data variables
        external_vars: Dict[str, tuple[int, str]] = {}
        
        for node in ast.walk(parsed_file.tree):
            # Track external data sources
            if isinstance(node, ast.Assign):
                source = self._is_external_data(node.value)
                if source:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            external_vars[target.id] = (node.lineno, source)
            
            # Check for external data in RAG/retrieval chains
            if isinstance(node, ast.Call):
                finding = self._check_rag_pattern(node, external_vars, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _is_external_data(self, node: ast.AST) -> Optional[str]:
        """Check if node retrieves external data."""
        
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            
            if func_name:
                if func_name in self.EXTERNAL_SOURCES:
                    return f".{func_name}()"
                if func_name in self.DOCUMENT_LOADERS:
                    return f"{func_name}"
        
        return None
    
    def _check_rag_pattern(
        self,
        node: ast.Call,
        external_vars: Dict[str, tuple[int, str]],
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check for RAG patterns without sanitization."""
        
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        # RAG chain patterns
        rag_patterns = {
            "RetrievalQA",
            "ConversationalRetrievalChain",
            "create_retrieval_chain",
            "load_qa_chain",
        }
        
        if func_name in rag_patterns:
            # RAG chains are susceptible to indirect injection
            return self.create_finding(
                title=f"RAG chain ({func_name}) vulnerable to indirect injection",
                description=(
                    f"RAG chains like {func_name} can be exploited if retrieved "
                    "documents contain malicious prompts. An attacker could plant "
                    "instructions in indexed content that manipulate the LLM."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "1. Sanitize retrieved content before including in prompts\n"
                    "2. Use content filtering to detect injection attempts\n"
                    "3. Implement source verification for indexed documents\n"
                    "4. Consider using structured extraction instead of raw content"
                ),
                confidence=0.8,
            )
        
        return None
