"""
Main scanner orchestration.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from agent_scanner.core.findings import Finding, ScanResult
from agent_scanner.core.parser import PythonParser
from agent_scanner.rules.base import Rule


class Scanner:
    """
    Main security scanner for AI agent code.
    
    Orchestrates parsing, rule execution, and result aggregation.
    """
    
    # File patterns to scan
    INCLUDE_PATTERNS = ["**/*.py"]
    
    # Patterns to exclude
    EXCLUDE_PATTERNS = [
        "**/venv/**",
        "**/.venv/**",
        "**/env/**",
        "**/.env/**",
        "**/node_modules/**",
        "**/__pycache__/**",
        "**/.git/**",
        "**/dist/**",
        "**/build/**",
        "**/*.egg-info/**",
        "**/site-packages/**",
    ]
    
    def __init__(self, rules: Optional[list[Rule]] = None):
        """
        Initialize the scanner.
        
        Args:
            rules: List of rules to run. If None, uses all registered rules.
        """
        self.rules = rules or self._load_all_rules()
        self.parser = PythonParser()
    
    def _load_all_rules(self) -> list[Rule]:
        """Load all registered security rules."""
        from agent_scanner.rules.registry import get_registry
        
        registry = get_registry()
        return registry.create_instances()
    
    def scan_path(self, path: Path, recursive: bool = True) -> ScanResult:
        """
        Scan a file or directory for security issues.
        
        Args:
            path: File or directory to scan
            recursive: Whether to scan subdirectories
            
        Returns:
            ScanResult with all findings
        """
        start_time = time.time()
        findings: list[Finding] = []
        errors: list[str] = []
        files_scanned = 0
        
        if path.is_file():
            files = [path]
        else:
            files = self._collect_files(path, recursive)
        
        for file_path in files:
            try:
                file_findings = self.scan_file(file_path)
                findings.extend(file_findings)
                files_scanned += 1
            except Exception as e:
                errors.append(f"Error scanning {file_path}: {e}")
        
        duration_ms = (time.time() - start_time) * 1000
        
        return ScanResult(
            findings=findings,
            files_scanned=files_scanned,
            scan_duration_ms=duration_ms,
            errors=errors,
        )
    
    def scan_file(self, file_path: Path) -> list[Finding]:
        """
        Scan a single file for security issues.
        
        Args:
            file_path: Path to the Python file
            
        Returns:
            List of findings from all rules
        """
        parsed = self.parser.parse_file(file_path)
        
        if parsed.errors:
            # Return a single finding for parse errors
            from agent_scanner.core.findings import Location, Severity
            return [
                Finding(
                    rule_id="ASS-000",
                    title="Parse Error",
                    severity=Severity.INFO,
                    description=f"Could not parse file: {'; '.join(parsed.errors)}",
                    location=Location(file=file_path, line=1, column=0),
                    fix_suggestion="Fix syntax errors before scanning",
                )
            ]
        
        findings: list[Finding] = []
        
        for rule in self.rules:
            try:
                rule_findings = rule.check(parsed)
                findings.extend(rule_findings)
            except Exception as e:
                # Don't let one rule crash the whole scan
                from agent_scanner.core.findings import Location, Severity
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=f"Rule Error: {rule.id}",
                        severity=Severity.INFO,
                        description=f"Rule {rule.id} failed: {e}",
                        location=Location(file=file_path, line=1, column=0),
                        fix_suggestion="This may be a bug in the scanner",
                    )
                )
        
        return findings
    
    def scan_source(self, source: str, filename: str = "<string>") -> list[Finding]:
        """
        Scan Python source code directly.
        
        Args:
            source: Python source code
            filename: Virtual filename for error messages
            
        Returns:
            List of findings
        """
        parsed = self.parser.parse_source(source, filename)
        
        findings: list[Finding] = []
        
        for rule in self.rules:
            try:
                rule_findings = rule.check(parsed)
                findings.extend(rule_findings)
            except Exception as e:
                from agent_scanner.core.findings import Location, Severity
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=f"Rule Error: {rule.id}",
                        severity=Severity.INFO,
                        description=f"Rule {rule.id} failed: {e}",
                        location=Location(file=Path(filename), line=1, column=0),
                        fix_suggestion="This may be a bug in the scanner",
                    )
                )
        
        return findings
    
    def _collect_files(self, directory: Path, recursive: bool) -> list[Path]:
        """Collect Python files to scan, respecting exclude patterns."""
        
        files: list[Path] = []
        
        for pattern in self.INCLUDE_PATTERNS:
            if recursive:
                matches = directory.glob(pattern)
            else:
                # Only match in the root directory
                matches = directory.glob(pattern.replace("**/", ""))
            
            for match in matches:
                if not self._is_excluded(match, directory):
                    files.append(match)
        
        return sorted(set(files))
    
    def _is_excluded(self, file_path: Path, base_dir: Path) -> bool:
        """Check if a file should be excluded from scanning."""
        
        try:
            relative = file_path.relative_to(base_dir)
        except ValueError:
            relative = file_path
        
        relative_str = str(relative)
        
        for pattern in self.EXCLUDE_PATTERNS:
            # Simple pattern matching
            pattern_parts = pattern.replace("**", "*").split("/")
            path_parts = relative_str.split("/")
            
            # Check if any pattern part matches any path part
            for pattern_part in pattern_parts:
                if pattern_part == "*":
                    continue
                for path_part in path_parts:
                    if pattern_part.replace("*", "") in path_part:
                        return True
        
        return False
