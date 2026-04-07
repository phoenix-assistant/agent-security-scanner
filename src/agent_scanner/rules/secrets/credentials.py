"""
Credentials Detection Rules.

Detects hardcoded passwords, connection strings, and other credentials.
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, Optional

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule
from agent_scanner.rules.registry import register_rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@register_rule
class HardcodedPasswordRule(Rule):
    """
    SEC-003: Hardcoded Password Detection
    
    Detects hardcoded passwords in source code.
    """
    
    id = "SEC-003"
    name = "Hardcoded Password"
    description = "Password appears to be hardcoded in source"
    severity = Severity.CRITICAL
    cwe_id = "CWE-798"
    owasp_id = "A07"
    
    # Password variable patterns
    PASSWORD_VAR_PATTERNS = {
        "password", "passwd", "pwd",
        "secret", "pass",
        "credentials", "cred",
        "auth_password", "db_password",
        "admin_password", "root_password",
    }
    
    # Common weak passwords to detect
    WEAK_PASSWORDS = {
        "password", "123456", "admin", "root",
        "test", "guest", "default", "changeme",
        "password123", "admin123", "letmein",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for hardcoded passwords."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            # Check assignments
            if isinstance(node, ast.Assign):
                finding = self._check_password_assignment(node, parsed_file)
                if finding:
                    findings.append(finding)
            
            # Check function calls with password parameters
            if isinstance(node, ast.Call):
                finding = self._check_password_argument(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_password_assignment(
        self,
        node: ast.Assign,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check for password variable assignments."""
        
        var_name = None
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                break
        
        if not var_name:
            return None
        
        # Check if variable name suggests password
        is_password_var = any(p in var_name for p in self.PASSWORD_VAR_PATTERNS)
        if not is_password_var:
            return None
        
        # Check if value is hardcoded
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            
            # Skip empty or placeholder values
            if not value or value in {"", "...", "xxx", "TODO"}:
                return None
            
            is_weak = value.lower() in self.WEAK_PASSWORDS
            
            return self.create_finding(
                title=f"Hardcoded password in '{node.targets[0].id}'",
                description=(
                    f"Variable '{node.targets[0].id}' is assigned a hardcoded password. "
                    + ("This is also a commonly used weak password!" if is_weak else "")
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "1. Never hardcode passwords in source code\n"
                    "2. Use environment variables or secrets management\n"
                    "3. Example: password = os.environ.get('DB_PASSWORD')"
                ),
            )
        
        return None
    
    def _check_password_argument(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check for hardcoded passwords in function arguments."""
        
        for kw in node.keywords:
            if not kw.arg:
                continue
            
            arg_lower = kw.arg.lower()
            is_password_arg = any(p in arg_lower for p in self.PASSWORD_VAR_PATTERNS)
            
            if is_password_arg:
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    value = kw.value.value
                    if value and value not in {"", "...", "xxx"}:
                        func_name = self._get_func_name(node)
                        return self.create_finding(
                            title=f"Hardcoded password in {func_name}({kw.arg}=...)",
                            description=(
                                f"Function {func_name}() called with hardcoded password "
                                f"in parameter '{kw.arg}'."
                            ),
                            file_path=parsed_file.path,
                            line=node.lineno,
                            column=node.col_offset,
                            fix_suggestion=(
                                f"Replace with:\n"
                                f"  {func_name}(..., {kw.arg}=os.environ['PASSWORD'])"
                            ),
                        )
        
        return None
    
    def _get_func_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return "function"


@register_rule
class HardcodedConnectionStringRule(Rule):
    """
    SEC-004: Hardcoded Connection String
    
    Detects hardcoded database connection strings with credentials.
    """
    
    id = "SEC-004"
    name = "Hardcoded Connection String"
    description = "Database connection string with credentials hardcoded"
    severity = Severity.CRITICAL
    cwe_id = "CWE-798"
    owasp_id = "A07"
    
    # Connection string patterns
    CONNECTION_PATTERNS = [
        # PostgreSQL
        (r"postgres(?:ql)?://[^:]+:[^@]+@[^\s]+", "PostgreSQL"),
        # MySQL
        (r"mysql://[^:]+:[^@]+@[^\s]+", "MySQL"),
        (r"mysql\+pymysql://[^:]+:[^@]+@[^\s]+", "MySQL/PyMySQL"),
        # MongoDB
        (r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+", "MongoDB"),
        # Redis
        (r"redis://:[^@]+@[^\s]+", "Redis"),
        (r"redis://[^:]+:[^@]+@[^\s]+", "Redis"),
        # SQL Server
        (r"mssql://[^:]+:[^@]+@[^\s]+", "SQL Server"),
        # SQLite with password
        (r"sqlite:///[^\s]+\?.*password=", "SQLite"),
        # Generic JDBC
        (r"jdbc:[a-z]+://[^:]+:[^@]+@[^\s]+", "JDBC"),
        # AMQP (RabbitMQ)
        (r"amqp://[^:]+:[^@]+@[^\s]+", "AMQP/RabbitMQ"),
    ]
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for hardcoded connection strings."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                finding = self._check_connection_string(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_connection_string(
        self,
        node: ast.Constant,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check if string is a connection string with credentials."""
        
        value = node.value
        if len(value) < 15:  # Too short
            return None
        
        for pattern, db_type in self.CONNECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                # Mask credentials in the connection string
                masked = self._mask_connection_string(value)
                
                return self.create_finding(
                    title=f"Hardcoded {db_type} connection string with credentials",
                    description=(
                        f"Connection string found: {masked}\n"
                        "Hardcoded credentials in connection strings are a critical risk."
                    ),
                    file_path=parsed_file.path,
                    line=node.lineno,
                    column=node.col_offset,
                    fix_suggestion=(
                        "1. Use environment variables for connection strings\n"
                        "2. Example:\n"
                        "   DATABASE_URL = os.environ['DATABASE_URL']\n"
                        "3. Or construct from individual env vars:\n"
                        "   f\"postgres://{user}:{os.environ['DB_PASS']}@{host}/{db}\""
                    ),
                )
        
        return None
    
    def _mask_connection_string(self, conn_str: str) -> str:
        """Mask credentials in connection string."""
        # Match user:password@ pattern
        pattern = r"(://[^:]+:)([^@]+)(@)"
        masked = re.sub(pattern, r"\1***\3", conn_str)
        
        # Truncate if too long
        if len(masked) > 60:
            masked = masked[:57] + "..."
        
        return masked
