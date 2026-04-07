"""
LangChain-specific pattern recognition.

Enhances analysis for LangChain agents, chains, and tools.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
import ast

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@dataclass
class LangChainComponent:
    """Represents a detected LangChain component."""
    
    component_type: str  # "agent", "chain", "tool", "prompt", etc.
    name: str
    line: int
    config: dict


class LangChainAdapter:
    """
    Adapter for LangChain-specific code analysis.
    
    Detects and extracts information about:
    - Agents (AgentExecutor, create_*_agent)
    - Chains (LLMChain, SequentialChain, etc.)
    - Tools (@tool decorator, BaseTool subclasses)
    - Prompts (ChatPromptTemplate, etc.)
    - Memory (ConversationBufferMemory, etc.)
    """
    
    # Agent creation patterns
    AGENT_PATTERNS = {
        "AgentExecutor",
        "create_react_agent",
        "create_openai_functions_agent",
        "create_structured_chat_agent",
        "create_tool_calling_agent",
        "initialize_agent",
        "ZeroShotAgent",
        "ConversationalAgent",
        "OpenAIFunctionsAgent",
    }
    
    # Chain patterns
    CHAIN_PATTERNS = {
        "LLMChain",
        "SequentialChain",
        "SimpleSequentialChain",
        "TransformChain",
        "RouterChain",
        "RetrievalQA",
        "ConversationalRetrievalChain",
    }
    
    # Tool patterns
    TOOL_DECORATORS = {"tool", "Tool"}
    TOOL_BASES = {"BaseTool", "Tool", "StructuredTool"}
    
    # Prompt patterns
    PROMPT_PATTERNS = {
        "ChatPromptTemplate",
        "PromptTemplate",
        "SystemMessagePromptTemplate",
        "HumanMessagePromptTemplate",
        "AIMessagePromptTemplate",
        "MessagesPlaceholder",
    }
    
    # Memory patterns
    MEMORY_PATTERNS = {
        "ConversationBufferMemory",
        "ConversationSummaryMemory",
        "ConversationBufferWindowMemory",
        "VectorStoreRetrieverMemory",
    }
    
    # High-risk LangChain tools
    HIGH_RISK_TOOLS = {
        "PythonREPLTool",
        "PythonREPL",
        "PythonAstREPLTool",
        "ShellTool",
        "BashProcess",
        "Terminal",
        "FileManagementToolkit",
        "WriteFileTool",
        "DeleteFileTool",
        "SQLDatabaseToolkit",
        "RequestsToolkit",
    }
    
    def __init__(self):
        self.components: list[LangChainComponent] = []
    
    def analyze(self, parsed_file: "ParsedFile") -> list[LangChainComponent]:
        """
        Analyze a file for LangChain components.
        
        Args:
            parsed_file: Parsed Python file
            
        Returns:
            List of detected LangChain components
        """
        self.components = []
        
        # Check if file uses LangChain
        if not self._uses_langchain(parsed_file):
            return []
        
        for node in ast.walk(parsed_file.tree):
            # Detect agents
            if isinstance(node, ast.Call):
                self._check_agent(node)
                self._check_chain(node)
                self._check_prompt(node)
                self._check_tool_instantiation(node)
            
            # Detect tool decorators
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._check_tool_decorator(node)
            
            # Detect tool classes
            if isinstance(node, ast.ClassDef):
                self._check_tool_class(node)
        
        return self.components
    
    def _uses_langchain(self, parsed_file: "ParsedFile") -> bool:
        """Check if the file imports LangChain."""
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "langchain" in alias.name:
                        return True
            if isinstance(node, ast.ImportFrom):
                if node.module and "langchain" in node.module:
                    return True
        return False
    
    def _check_agent(self, node: ast.Call):
        """Check for agent creation."""
        func_name = self._get_func_name(node)
        if func_name in self.AGENT_PATTERNS:
            config = self._extract_agent_config(node)
            self.components.append(LangChainComponent(
                component_type="agent",
                name=func_name,
                line=node.lineno,
                config=config,
            ))
    
    def _check_chain(self, node: ast.Call):
        """Check for chain creation."""
        func_name = self._get_func_name(node)
        if func_name in self.CHAIN_PATTERNS:
            self.components.append(LangChainComponent(
                component_type="chain",
                name=func_name,
                line=node.lineno,
                config={},
            ))
    
    def _check_prompt(self, node: ast.Call):
        """Check for prompt template creation."""
        func_name = self._get_func_name(node)
        if func_name in self.PROMPT_PATTERNS:
            self.components.append(LangChainComponent(
                component_type="prompt",
                name=func_name,
                line=node.lineno,
                config={},
            ))
    
    def _check_tool_instantiation(self, node: ast.Call):
        """Check for tool instantiation."""
        func_name = self._get_func_name(node)
        if func_name in self.HIGH_RISK_TOOLS:
            self.components.append(LangChainComponent(
                component_type="high_risk_tool",
                name=func_name,
                line=node.lineno,
                config={"risk": "high"},
            ))
    
    def _check_tool_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Check for @tool decorated functions."""
        for dec in node.decorator_list:
            dec_name = None
            if isinstance(dec, ast.Name):
                dec_name = dec.id
            elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                dec_name = dec.func.id
            
            if dec_name in self.TOOL_DECORATORS:
                self.components.append(LangChainComponent(
                    component_type="tool",
                    name=node.name,
                    line=node.lineno,
                    config={"decorator": True},
                ))
                break
    
    def _check_tool_class(self, node: ast.ClassDef):
        """Check for BaseTool subclasses."""
        bases = self._get_base_names(node)
        if any(b in self.TOOL_BASES for b in bases):
            self.components.append(LangChainComponent(
                component_type="tool",
                name=node.name,
                line=node.lineno,
                config={"class": True, "bases": bases},
            ))
    
    def _get_func_name(self, node: ast.Call) -> str | None:
        """Get function name from a call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
    
    def _get_base_names(self, node: ast.ClassDef) -> list[str]:
        """Get base class names."""
        names = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                names.append(base.id)
            elif isinstance(base, ast.Attribute):
                names.append(base.attr)
        return names
    
    def _extract_agent_config(self, node: ast.Call) -> dict:
        """Extract configuration from an agent creation call."""
        config = {}
        
        # Look for tools argument
        for kw in node.keywords:
            if kw.arg == "tools":
                config["tools_count"] = self._count_list_items(kw.value)
            elif kw.arg == "verbose":
                config["verbose"] = True
            elif kw.arg == "max_iterations":
                if isinstance(kw.value, ast.Constant):
                    config["max_iterations"] = kw.value.value
        
        return config
    
    def _count_list_items(self, node: ast.AST) -> int:
        """Count items in a list expression."""
        if isinstance(node, ast.List):
            return len(node.elts)
        return -1  # Unknown
    
    def get_tools(self) -> list[LangChainComponent]:
        """Get all detected tools."""
        return [c for c in self.components if c.component_type in ("tool", "high_risk_tool")]
    
    def get_agents(self) -> list[LangChainComponent]:
        """Get all detected agents."""
        return [c for c in self.components if c.component_type == "agent"]
    
    def get_high_risk_tools(self) -> list[LangChainComponent]:
        """Get all high-risk tools."""
        return [c for c in self.components if c.component_type == "high_risk_tool"]
