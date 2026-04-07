"""SARIF output format for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_scanner.core.findings import ScanResult, Severity
from agent_scanner import __version__


class SarifOutput:
    """
    Generates SARIF (Static Analysis Results Interchange Format) output.
    
    SARIF is used by GitHub Code Scanning and other CI/CD tools.
    Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """
    
    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
    
    def __init__(self, base_path: Path | None = None):
        """
        Initialize SARIF output.
        
        Args:
            base_path: Base path for relative file paths. If None, uses absolute paths.
        """
        self.base_path = base_path
    
    def generate(self, result: ScanResult) -> dict[str, Any]:
        """Generate SARIF output from scan results."""
        
        return {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [self._create_run(result)],
        }
    
    def to_json(self, result: ScanResult, indent: int = 2) -> str:
        """Generate SARIF output as a JSON string."""
        return json.dumps(self.generate(result), indent=indent)
    
    def write(self, result: ScanResult, output_path: Path):
        """Write SARIF output to a file."""
        output_path.write_text(self.to_json(result))
    
    def _create_run(self, result: ScanResult) -> dict[str, Any]:
        """Create a SARIF run object."""
        
        # Collect unique rules
        rules_seen = {}
        for finding in result.findings:
            if finding.rule_id not in rules_seen:
                rules_seen[finding.rule_id] = finding
        
        return {
            "tool": {
                "driver": {
                    "name": "Agent Security Scanner",
                    "version": __version__,
                    "informationUri": "https://github.com/phoenix-assistant/agent-security-scanner",
                    "rules": [
                        self._create_rule(finding)
                        for finding in rules_seen.values()
                    ],
                }
            },
            "results": [
                self._create_result(finding)
                for finding in result.findings
                if not finding.suppressed
            ],
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    {"level": "warning", "message": {"text": error}}
                    for error in result.errors
                ],
            }],
        }
    
    def _create_rule(self, finding) -> dict[str, Any]:
        """Create a SARIF rule definition."""
        
        rule = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {
                "text": finding.title,
            },
            "fullDescription": {
                "text": finding.description,
            },
            "defaultConfiguration": {
                "level": finding.severity.sarif_level,
            },
            "help": {
                "text": finding.fix_suggestion,
                "markdown": f"**Fix:** {finding.fix_suggestion}",
            },
        }
        
        # Add properties for OWASP/CWE
        properties = {}
        if finding.owasp_id:
            properties["security-severity"] = self._severity_score(finding.severity)
            properties["tags"] = [f"owasp-llm-{finding.owasp_id.lower()}"]
        if finding.cwe_id:
            properties.setdefault("tags", []).append(finding.cwe_id.lower())
        
        if properties:
            rule["properties"] = properties
        
        return rule
    
    def _create_result(self, finding) -> dict[str, Any]:
        """Create a SARIF result object."""
        
        # Calculate relative path if base_path is set
        file_path = finding.location.file
        if self.base_path:
            try:
                file_path = file_path.relative_to(self.base_path)
            except ValueError:
                pass  # Keep absolute path
        
        result = {
            "ruleId": finding.rule_id,
            "level": finding.severity.sarif_level,
            "message": {
                "text": finding.description,
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(file_path),
                    },
                    "region": {
                        "startLine": finding.location.line,
                        "startColumn": finding.location.column + 1,  # SARIF is 1-indexed
                    },
                },
            }],
        }
        
        # Add end line/column if available
        if finding.location.end_line:
            result["locations"][0]["physicalLocation"]["region"]["endLine"] = finding.location.end_line
        if finding.location.end_column:
            result["locations"][0]["physicalLocation"]["region"]["endColumn"] = finding.location.end_column + 1
        
        # Add code snippet if available
        if finding.location.snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.location.snippet,
            }
        
        # Add properties
        result["properties"] = {
            "confidence": finding.confidence,
        }
        
        return result
    
    def _severity_score(self, severity: Severity) -> str:
        """Convert severity to SARIF security-severity score (0.0-10.0)."""
        return {
            Severity.CRITICAL: "9.0",
            Severity.HIGH: "7.0",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "3.0",
            Severity.INFO: "1.0",
        }[severity]
