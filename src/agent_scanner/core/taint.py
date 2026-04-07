"""
Taint tracking for data flow analysis.

This module implements simplified taint tracking to identify when untrusted
data flows to sensitive sinks without proper validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional
import ast


class TaintType(Enum):
    """Types of taint sources."""
    
    USER_INPUT = auto()        # Direct user input (input(), request.*)
    TOOL_OUTPUT = auto()       # Output from agent tools
    WEB_CONTENT = auto()       # Scraped web content
    FILE_CONTENT = auto()      # File reads
    API_RESPONSE = auto()      # External API responses
    DATABASE = auto()          # Database query results
    ENVIRONMENT = auto()       # Environment variables
    UNKNOWN = auto()           # Unclassified external data


class SinkType(Enum):
    """Types of sensitive sinks."""
    
    LLM_PROMPT = auto()        # System/user prompt content
    CODE_EXECUTION = auto()    # exec(), eval(), subprocess
    FILE_WRITE = auto()        # File system writes
    DATABASE_QUERY = auto()    # SQL queries
    SHELL_COMMAND = auto()     # Shell command execution
    NETWORK_REQUEST = auto()   # Outbound network requests
    TOOL_INPUT = auto()        # Input to another tool


@dataclass
class TaintSource:
    """A source of tainted data."""
    
    node: ast.AST
    taint_type: TaintType
    variable_name: str
    file: Path
    line: int
    column: int
    description: str
    
    def __hash__(self):
        return hash((str(self.file), self.line, self.column, self.variable_name))


@dataclass
class TaintSink:
    """A sensitive sink that should not receive tainted data."""
    
    node: ast.AST
    sink_type: SinkType
    file: Path
    line: int
    column: int
    description: str
    requires_validation: bool = True
    
    def __hash__(self):
        return hash((str(self.file), self.line, self.column))


@dataclass
class TaintedVariable:
    """Tracks a variable that carries tainted data."""
    
    name: str
    source: TaintSource
    scope: Optional[str] = None  # Function/class scope
    transformed: bool = False    # Has been through sanitization
    
    def __hash__(self):
        return hash((self.name, self.scope))


@dataclass
class TaintFlow:
    """A flow of tainted data from source to sink."""
    
    source: TaintSource
    sink: TaintSink
    path: list[str] = field(default_factory=list)  # Variable names in the flow
    validated: bool = False  # Was validation detected?
    
    def __str__(self) -> str:
        path_str = " → ".join(self.path) if self.path else "direct"
        return f"{self.source.description} → {path_str} → {self.sink.description}"


class TaintTracker:
    """
    Tracks tainted data through a Python AST.
    
    This is a simplified implementation that:
    1. Identifies sources of untrusted data
    2. Tracks variable assignments
    3. Detects when tainted data reaches sensitive sinks
    4. Recognizes common validation/sanitization patterns
    """
    
    def __init__(self):
        self.sources: list[TaintSource] = []
        self.sinks: list[TaintSink] = []
        self.tainted_vars: dict[str, TaintedVariable] = {}
        self.flows: list[TaintFlow] = []
        self._current_file: Optional[Path] = None
        self._current_scope: Optional[str] = None
    
    # --- Source Patterns ---
    
    # Functions that return user/external input
    SOURCE_FUNCTIONS = {
        "input": TaintType.USER_INPUT,
        "raw_input": TaintType.USER_INPUT,
    }
    
    # Attribute patterns that indicate external data
    SOURCE_ATTRIBUTES = {
        ("request", "args"): TaintType.USER_INPUT,
        ("request", "form"): TaintType.USER_INPUT,
        ("request", "json"): TaintType.USER_INPUT,
        ("request", "data"): TaintType.USER_INPUT,
        ("request", "query"): TaintType.USER_INPUT,
        ("os", "environ"): TaintType.ENVIRONMENT,
    }
    
    # Method calls that return external data
    SOURCE_METHODS = {
        "get": TaintType.API_RESPONSE,  # requests.get()
        "post": TaintType.API_RESPONSE,
        "read": TaintType.FILE_CONTENT,
        "readline": TaintType.FILE_CONTENT,
        "readlines": TaintType.FILE_CONTENT,
        "fetchone": TaintType.DATABASE,
        "fetchall": TaintType.DATABASE,
        "fetchmany": TaintType.DATABASE,
    }
    
    # --- Sink Patterns ---
    
    # Functions that are dangerous sinks
    SINK_FUNCTIONS = {
        "exec": SinkType.CODE_EXECUTION,
        "eval": SinkType.CODE_EXECUTION,
        "compile": SinkType.CODE_EXECUTION,
    }
    
    # Method patterns that are dangerous sinks
    SINK_METHODS = {
        "invoke": SinkType.LLM_PROMPT,    # llm.invoke()
        "run": SinkType.TOOL_INPUT,        # tool.run()
        "execute": SinkType.DATABASE_QUERY,
        "system": SinkType.SHELL_COMMAND,
        "popen": SinkType.SHELL_COMMAND,
        "call": SinkType.SHELL_COMMAND,    # subprocess.call()
        "write": SinkType.FILE_WRITE,
    }
    
    # --- Validation Patterns ---
    
    VALIDATION_FUNCTIONS = {
        "sanitize", "validate", "escape", "clean",
        "strip", "filter", "safe", "encode",
        "quote", "htmlescape", "bleach",
    }
    
    def track_file(self, file_path: Path, tree: ast.AST) -> list[TaintFlow]:
        """
        Analyze a file's AST for taint flows.
        
        Args:
            file_path: Path to the source file
            tree: Parsed AST
            
        Returns:
            List of taint flows detected
        """
        self._current_file = file_path
        self.sources = []
        self.sinks = []
        self.tainted_vars = {}
        self.flows = []
        
        # First pass: identify sources and sinks
        self._identify_sources_sinks(tree)
        
        # Second pass: track variable assignments and flows
        self._track_assignments(tree)
        
        # Third pass: detect flows from sources to sinks
        self._detect_flows(tree)
        
        return self.flows
    
    def _identify_sources_sinks(self, tree: ast.AST):
        """First pass: identify all sources and sinks in the AST."""
        
        for node in ast.walk(tree):
            # Check for source patterns
            source = self._check_source(node)
            if source:
                self.sources.append(source)
            
            # Check for sink patterns
            sink = self._check_sink(node)
            if sink:
                self.sinks.append(sink)
    
    def _check_source(self, node: ast.AST) -> Optional[TaintSource]:
        """Check if a node is a taint source."""
        
        # Function calls: input(), etc.
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in self.SOURCE_FUNCTIONS:
                    return TaintSource(
                        node=node,
                        taint_type=self.SOURCE_FUNCTIONS[node.func.id],
                        variable_name="<direct>",
                        file=self._current_file or Path("unknown"),
                        line=node.lineno,
                        column=node.col_offset,
                        description=f"User input from {node.func.id}()",
                    )
            
            # Method calls: requests.get(), file.read(), etc.
            if isinstance(node.func, ast.Attribute):
                method_name = node.func.attr
                if method_name in self.SOURCE_METHODS:
                    return TaintSource(
                        node=node,
                        taint_type=self.SOURCE_METHODS[method_name],
                        variable_name="<direct>",
                        file=self._current_file or Path("unknown"),
                        line=node.lineno,
                        column=node.col_offset,
                        description=f"External data from .{method_name}()",
                    )
        
        # Attribute access: request.form, os.environ, etc.
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                attr_name = node.value.attr
                if isinstance(node.value.value, ast.Name):
                    obj_name = node.value.value.id
                    key = (obj_name, attr_name)
                    if key in self.SOURCE_ATTRIBUTES:
                        return TaintSource(
                            node=node,
                            taint_type=self.SOURCE_ATTRIBUTES[key],
                            variable_name="<direct>",
                            file=self._current_file or Path("unknown"),
                            line=node.lineno,
                            column=node.col_offset,
                            description=f"External data from {obj_name}.{attr_name}",
                        )
        
        return None
    
    def _check_sink(self, node: ast.AST) -> Optional[TaintSink]:
        """Check if a node is a sensitive sink."""
        
        if isinstance(node, ast.Call):
            # Direct function calls: exec(), eval()
            if isinstance(node.func, ast.Name):
                if node.func.id in self.SINK_FUNCTIONS:
                    return TaintSink(
                        node=node,
                        sink_type=self.SINK_FUNCTIONS[node.func.id],
                        file=self._current_file or Path("unknown"),
                        line=node.lineno,
                        column=node.col_offset,
                        description=f"Code execution via {node.func.id}()",
                    )
            
            # Method calls: llm.invoke(), subprocess.call()
            if isinstance(node.func, ast.Attribute):
                method_name = node.func.attr
                if method_name in self.SINK_METHODS:
                    return TaintSink(
                        node=node,
                        sink_type=self.SINK_METHODS[method_name],
                        file=self._current_file or Path("unknown"),
                        line=node.lineno,
                        column=node.col_offset,
                        description=f"Sensitive operation via .{method_name}()",
                    )
        
        return None
    
    def _track_assignments(self, tree: ast.AST):
        """Track which variables receive tainted data."""
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Check if the value is a tainted source
                for source in self.sources:
                    if self._nodes_equivalent(node.value, source.node):
                        # Mark all targets as tainted
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                self.tainted_vars[target.id] = TaintedVariable(
                                    name=target.id,
                                    source=source,
                                    scope=self._current_scope,
                                )
            
            # Track taint propagation through assignments
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        tainted_in_value = self._find_tainted_in_expr(node.value)
                        if tainted_in_value:
                            # Check if there's validation
                            validated = self._has_validation(node.value)
                            if not validated:
                                self.tainted_vars[target.id] = TaintedVariable(
                                    name=target.id,
                                    source=tainted_in_value.source,
                                    scope=self._current_scope,
                                    transformed=True,
                                )
    
    def _detect_flows(self, tree: ast.AST):
        """Detect when tainted data flows to sinks."""
        
        for sink in self.sinks:
            if isinstance(sink.node, ast.Call):
                # Check arguments to the sink
                for arg in sink.node.args:
                    tainted = self._find_tainted_in_expr(arg)
                    if tainted:
                        # Check if there's validation between source and sink
                        validated = self._has_validation(arg)
                        
                        flow = TaintFlow(
                            source=tainted.source,
                            sink=sink,
                            path=[tainted.name],
                            validated=validated,
                        )
                        
                        if not validated:
                            self.flows.append(flow)
                
                # Check keyword arguments
                for kw in sink.node.keywords:
                    tainted = self._find_tainted_in_expr(kw.value)
                    if tainted:
                        validated = self._has_validation(kw.value)
                        
                        flow = TaintFlow(
                            source=tainted.source,
                            sink=sink,
                            path=[tainted.name],
                            validated=validated,
                        )
                        
                        if not validated:
                            self.flows.append(flow)
    
    def _find_tainted_in_expr(self, expr: ast.AST) -> Optional[TaintedVariable]:
        """Check if an expression contains tainted data."""
        
        if isinstance(expr, ast.Name):
            return self.tainted_vars.get(expr.id)
        
        # Recursively check sub-expressions
        for child in ast.walk(expr):
            if isinstance(child, ast.Name):
                if child.id in self.tainted_vars:
                    return self.tainted_vars[child.id]
        
        return None
    
    def _has_validation(self, expr: ast.AST) -> bool:
        """Check if an expression has been through validation."""
        
        # Look for validation function calls in the expression tree
        for node in ast.walk(expr):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if any(v in node.func.id.lower() for v in self.VALIDATION_FUNCTIONS):
                        return True
                if isinstance(node.func, ast.Attribute):
                    if any(v in node.func.attr.lower() for v in self.VALIDATION_FUNCTIONS):
                        return True
        
        return False
    
    def _nodes_equivalent(self, node1: ast.AST, node2: ast.AST) -> bool:
        """Check if two AST nodes are equivalent (same location)."""
        return (
            hasattr(node1, 'lineno') and hasattr(node2, 'lineno') and
            node1.lineno == node2.lineno and
            hasattr(node1, 'col_offset') and hasattr(node2, 'col_offset') and
            node1.col_offset == node2.col_offset
        )
