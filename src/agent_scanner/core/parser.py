"""
Python AST parsing utilities for agent code analysis.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ParsedFile:
    """A parsed Python source file."""
    
    path: Path
    tree: ast.AST
    source: str
    errors: list[str] = field(default_factory=list)
    
    def get_snippet(self, line: int, context: int = 2) -> str:
        """Get a code snippet around a specific line."""
        lines = self.source.splitlines()
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        
        result = []
        for i, src_line in enumerate(lines[start:end], start=start + 1):
            marker = "→ " if i == line else "  "
            result.append(f"{marker}{i:4d} | {src_line}")
        
        return "\n".join(result)


@dataclass
class ImportInfo:
    """Information about an import statement."""
    
    module: str
    name: Optional[str]  # None for "import module", name for "from module import name"
    alias: Optional[str]
    line: int


@dataclass
class FunctionInfo:
    """Information about a function definition."""
    
    name: str
    line: int
    decorators: list[str]
    parameters: list[str]
    is_async: bool
    docstring: Optional[str]


@dataclass
class ClassInfo:
    """Information about a class definition."""
    
    name: str
    line: int
    bases: list[str]
    decorators: list[str]
    methods: list[FunctionInfo]


class PythonParser:
    """
    Parser for Python source files.
    
    Extracts structural information useful for security analysis:
    - Imports (to identify frameworks)
    - Function/class definitions (to find tools, agents)
    - Decorators (to identify LangChain @tool, etc.)
    """
    
    def __init__(self):
        self.imports: list[ImportInfo] = []
        self.functions: list[FunctionInfo] = []
        self.classes: list[ClassInfo] = []
    
    def parse_file(self, file_path: Path) -> ParsedFile:
        """Parse a Python file and extract structural information."""
        
        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception as e:
            return ParsedFile(
                path=file_path,
                tree=ast.Module(body=[], type_ignores=[]),
                source="",
                errors=[f"Could not read file: {e}"],
            )
        
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as e:
            return ParsedFile(
                path=file_path,
                tree=ast.Module(body=[], type_ignores=[]),
                source=source,
                errors=[f"Syntax error at line {e.lineno}: {e.msg}"],
            )
        
        # Extract structural info
        self._extract_info(tree)
        
        return ParsedFile(path=file_path, tree=tree, source=source)
    
    def parse_source(self, source: str, filename: str = "<string>") -> ParsedFile:
        """Parse Python source code directly."""
        
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as e:
            return ParsedFile(
                path=Path(filename),
                tree=ast.Module(body=[], type_ignores=[]),
                source=source,
                errors=[f"Syntax error at line {e.lineno}: {e.msg}"],
            )
        
        self._extract_info(tree)
        
        return ParsedFile(path=Path(filename), tree=tree, source=source)
    
    def _extract_info(self, tree: ast.AST):
        """Extract structural information from the AST."""
        
        self.imports = []
        self.functions = []
        self.classes = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports.append(ImportInfo(
                        module=alias.name,
                        name=None,
                        alias=alias.asname,
                        line=node.lineno,
                    ))
            
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    self.imports.append(ImportInfo(
                        module=module,
                        name=alias.name,
                        alias=alias.asname,
                        line=node.lineno,
                    ))
            
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorators = []
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Name):
                        decorators.append(dec.id)
                    elif isinstance(dec, ast.Attribute):
                        decorators.append(dec.attr)
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Name):
                            decorators.append(dec.func.id)
                        elif isinstance(dec.func, ast.Attribute):
                            decorators.append(dec.func.attr)
                
                params = [arg.arg for arg in node.args.args]
                
                docstring = ast.get_docstring(node)
                
                self.functions.append(FunctionInfo(
                    name=node.name,
                    line=node.lineno,
                    decorators=decorators,
                    parameters=params,
                    is_async=isinstance(node, ast.AsyncFunctionDef),
                    docstring=docstring,
                ))
            
            elif isinstance(node, ast.ClassDef):
                decorators = []
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Name):
                        decorators.append(dec.id)
                    elif isinstance(dec, ast.Attribute):
                        decorators.append(dec.attr)
                
                bases = []
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        bases.append(base.id)
                    elif isinstance(base, ast.Attribute):
                        bases.append(base.attr)
                
                methods = []
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_decorators = []
                        for dec in item.decorator_list:
                            if isinstance(dec, ast.Name):
                                method_decorators.append(dec.id)
                        
                        methods.append(FunctionInfo(
                            name=item.name,
                            line=item.lineno,
                            decorators=method_decorators,
                            parameters=[arg.arg for arg in item.args.args],
                            is_async=isinstance(item, ast.AsyncFunctionDef),
                            docstring=ast.get_docstring(item),
                        ))
                
                self.classes.append(ClassInfo(
                    name=node.name,
                    line=node.lineno,
                    bases=bases,
                    decorators=decorators,
                    methods=methods,
                ))
    
    def has_import(self, module_name: str) -> bool:
        """Check if a module is imported."""
        for imp in self.imports:
            if imp.module == module_name or imp.module.startswith(f"{module_name}."):
                return True
        return False
    
    def has_decorator(self, decorator_name: str) -> bool:
        """Check if any function has a specific decorator."""
        for func in self.functions:
            if decorator_name in func.decorators:
                return True
        for cls in self.classes:
            if decorator_name in cls.decorators:
                return True
            for method in cls.methods:
                if decorator_name in method.decorators:
                    return True
        return False
    
    def get_functions_with_decorator(self, decorator_name: str) -> list[FunctionInfo]:
        """Get all functions with a specific decorator."""
        result = []
        for func in self.functions:
            if decorator_name in func.decorators:
                result.append(func)
        return result
