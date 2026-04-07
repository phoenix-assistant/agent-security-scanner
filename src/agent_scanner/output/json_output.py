"""JSON output format for programmatic consumption."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_scanner.core.findings import ScanResult
from agent_scanner import __version__


class JsonOutput:
    """Simple JSON output format for scan results."""
    
    def __init__(self, base_path: Path | None = None):
        self.base_path = base_path
    
    def generate(self, result: ScanResult) -> dict[str, Any]:
        """Generate JSON output from scan results."""
        
        return {
            "version": __version__,
            "summary": {
                "files_scanned": result.files_scanned,
                "scan_duration_ms": result.scan_duration_ms,
                "total_findings": len(result.findings),
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "has_blocking_issues": result.has_blocking_issues,
            },
            "findings": [
                self._finding_to_dict(f)
                for f in result.findings
                if not f.suppressed
            ],
            "errors": result.errors,
        }
    
    def to_json(self, result: ScanResult, indent: int = 2) -> str:
        """Generate JSON output as a string."""
        return json.dumps(self.generate(result), indent=indent)
    
    def write(self, result: ScanResult, output_path: Path):
        """Write JSON output to a file."""
        output_path.write_text(self.to_json(result))
    
    def _finding_to_dict(self, finding) -> dict[str, Any]:
        """Convert a finding to a dictionary."""
        
        file_path = finding.location.file
        if self.base_path:
            try:
                file_path = file_path.relative_to(self.base_path)
            except ValueError:
                pass
        
        return {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "description": finding.description,
            "file": str(file_path),
            "line": finding.location.line,
            "column": finding.location.column,
            "fix_suggestion": finding.fix_suggestion,
            "confidence": finding.confidence,
            "cwe_id": finding.cwe_id,
            "owasp_id": finding.owasp_id,
        }
