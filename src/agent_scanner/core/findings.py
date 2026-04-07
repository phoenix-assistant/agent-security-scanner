"""Finding data structures for security issues."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    """Severity levels aligned with CVSS-like classification."""
    
    CRITICAL = "critical"  # Immediate exploitation possible
    HIGH = "high"          # Serious vulnerability, exploitation likely
    MEDIUM = "medium"      # Notable security concern
    LOW = "low"            # Minor issue, defense in depth
    INFO = "info"          # Informational, not a vulnerability
    
    @property
    def color(self) -> str:
        """Rich color for console output."""
        return {
            Severity.CRITICAL: "red bold",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]
    
    @property
    def sarif_level(self) -> str:
        """SARIF severity level."""
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }[self]


@dataclass
class Location:
    """Source code location for a finding."""
    
    file: Path
    line: int
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    snippet: Optional[str] = None
    
    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.column}"


@dataclass
class DataFlow:
    """Tracks data flow from source to sink."""
    
    source: Location
    source_description: str
    sink: Location
    sink_description: str
    intermediate_steps: list[Location] = field(default_factory=list)
    
    def __str__(self) -> str:
        steps = len(self.intermediate_steps)
        return f"{self.source_description} → ({steps} steps) → {self.sink_description}"


@dataclass
class Finding:
    """A security finding from the scanner."""
    
    rule_id: str
    title: str
    severity: Severity
    description: str
    location: Location
    fix_suggestion: str
    data_flow: Optional[DataFlow] = None
    confidence: float = 1.0  # 0.0-1.0, how sure we are
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    cwe_id: Optional[str] = None  # CWE reference
    owasp_id: Optional[str] = None  # OWASP LLM Top 10 reference
    
    def __str__(self) -> str:
        return f"[{self.rule_id}] {self.title} at {self.location}"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON/SARIF output."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "location": {
                "file": str(self.location.file),
                "line": self.location.line,
                "column": self.location.column,
                "snippet": self.location.snippet,
            },
            "fix_suggestion": self.fix_suggestion,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "owasp_id": self.owasp_id,
        }


@dataclass
class ScanResult:
    """Result of scanning a codebase."""
    
    findings: list[Finding]
    files_scanned: int
    scan_duration_ms: float
    errors: list[str] = field(default_factory=list)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL and not f.suppressed)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH and not f.suppressed)
    
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM and not f.suppressed)
    
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW and not f.suppressed)
    
    @property
    def has_blocking_issues(self) -> bool:
        """Returns True if there are CRITICAL or HIGH severity issues."""
        return self.critical_count > 0 or self.high_count > 0
    
    def summary(self) -> str:
        """Human-readable summary."""
        total = len([f for f in self.findings if not f.suppressed])
        return (
            f"Found {total} issues: "
            f"{self.critical_count} critical, "
            f"{self.high_count} high, "
            f"{self.medium_count} medium, "
            f"{self.low_count} low"
        )
