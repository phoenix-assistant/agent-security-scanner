"""Base class for security rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

from agent_scanner.core.findings import Finding, Severity

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


class Rule(ABC):
    """
    Abstract base class for security rules.
    
    Each rule implements a specific security check and produces
    findings when issues are detected.
    """
    
    # Rule metadata - override in subclasses
    id: str = "ASS-000"
    name: str = "Base Rule"
    description: str = "Base rule description"
    severity: Severity = Severity.MEDIUM
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None  # OWASP LLM Top 10 reference
    
    @abstractmethod
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """
        Run this rule against a parsed file.
        
        Args:
            parsed_file: The parsed Python file to check
            
        Returns:
            List of findings (empty if no issues found)
        """
        pass
    
    def create_finding(
        self,
        title: str,
        description: str,
        file_path,
        line: int,
        column: int = 0,
        fix_suggestion: str = "",
        snippet: Optional[str] = None,
        confidence: float = 1.0,
    ) -> Finding:
        """
        Helper to create a finding with this rule's metadata.
        
        Args:
            title: Short title for the finding
            description: Detailed description
            file_path: Path to the file
            line: Line number
            column: Column number
            fix_suggestion: How to fix the issue
            snippet: Code snippet showing the issue
            confidence: Confidence level (0.0-1.0)
            
        Returns:
            A Finding object
        """
        from agent_scanner.core.findings import Location
        
        return Finding(
            rule_id=self.id,
            title=title,
            severity=self.severity,
            description=description,
            location=Location(
                file=file_path,
                line=line,
                column=column,
                snippet=snippet,
            ),
            fix_suggestion=fix_suggestion,
            confidence=confidence,
            cwe_id=self.cwe_id,
            owasp_id=self.owasp_id,
        )
