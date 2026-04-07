"""
Baseline management for suppressing known findings.

Allows teams to acknowledge existing findings and focus on new ones.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from agent_scanner.core.findings import Finding


@dataclass
class BaselineEntry:
    """A single baselined finding."""
    
    fingerprint: str
    rule_id: str
    file_path: str
    line: Optional[int]
    title: str
    reason: str = ""  # Why it's baselined
    added_by: str = ""
    added_at: str = ""
    expires_at: Optional[str] = None  # Optional expiration
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line": self.line,
            "title": self.title,
            "reason": self.reason,
            "added_by": self.added_by,
            "added_at": self.added_at,
            "expires_at": self.expires_at,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaselineEntry":
        """Create from dictionary."""
        return cls(
            fingerprint=data["fingerprint"],
            rule_id=data["rule_id"],
            file_path=data["file_path"],
            line=data.get("line"),
            title=data["title"],
            reason=data.get("reason", ""),
            added_by=data.get("added_by", ""),
            added_at=data.get("added_at", ""),
            expires_at=data.get("expires_at"),
        )


@dataclass
class Baseline:
    """Collection of baselined findings."""
    
    version: str = "1.0"
    entries: Dict[str, BaselineEntry] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    
    def add(
        self,
        finding: Finding,
        reason: str = "",
        added_by: str = "",
        expires_at: Optional[str] = None,
    ) -> BaselineEntry:
        """Add a finding to the baseline."""
        fingerprint = self.compute_fingerprint(finding)
        
        entry = BaselineEntry(
            fingerprint=fingerprint,
            rule_id=finding.rule_id,
            file_path=str(finding.file_path),
            line=finding.line,
            title=finding.title,
            reason=reason,
            added_by=added_by,
            added_at=datetime.now().isoformat(),
            expires_at=expires_at,
        )
        
        self.entries[fingerprint] = entry
        self.updated_at = datetime.now().isoformat()
        
        return entry
    
    def remove(self, fingerprint: str) -> bool:
        """Remove a finding from the baseline."""
        if fingerprint in self.entries:
            del self.entries[fingerprint]
            self.updated_at = datetime.now().isoformat()
            return True
        return False
    
    def is_baselined(self, finding: Finding) -> bool:
        """Check if a finding is baselined."""
        fingerprint = self.compute_fingerprint(finding)
        
        if fingerprint not in self.entries:
            return False
        
        entry = self.entries[fingerprint]
        
        # Check expiration
        if entry.expires_at:
            try:
                expires = datetime.fromisoformat(entry.expires_at)
                if datetime.now() > expires:
                    return False
            except ValueError:
                pass
        
        return True
    
    def filter_findings(
        self,
        findings: List[Finding],
    ) -> tuple[List[Finding], List[Finding]]:
        """
        Filter findings against baseline.
        
        Returns:
            Tuple of (new_findings, baselined_findings)
        """
        new_findings = []
        baselined = []
        
        for finding in findings:
            if self.is_baselined(finding):
                baselined.append(finding)
            else:
                new_findings.append(finding)
        
        return new_findings, baselined
    
    @staticmethod
    def compute_fingerprint(finding: Finding) -> str:
        """
        Compute a stable fingerprint for a finding.
        
        The fingerprint should be stable across minor code changes
        but change if the actual issue changes.
        """
        # Use rule + file + title as the base
        # Don't include line number as it changes frequently
        data = f"{finding.rule_id}:{finding.file_path}:{finding.title}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "entries": {
                fp: entry.to_dict()
                for fp, entry in self.entries.items()
            },
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Baseline":
        """Create from dictionary."""
        baseline = cls(
            version=data.get("version", "1.0"),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )
        
        for fp, entry_data in data.get("entries", {}).items():
            baseline.entries[fp] = BaselineEntry.from_dict(entry_data)
        
        return baseline
    
    def save(self, path: Path) -> None:
        """Save baseline to file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, path: Path) -> "Baseline":
        """Load baseline from file."""
        if not path.exists():
            baseline = cls()
            baseline.created_at = datetime.now().isoformat()
            return baseline
        
        with open(path) as f:
            data = json.load(f)
        
        return cls.from_dict(data)


def create_baseline_from_findings(
    findings: List[Finding],
    reason: str = "Initial baseline",
) -> Baseline:
    """Create a new baseline from a list of findings."""
    baseline = Baseline(
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
    )
    
    for finding in findings:
        baseline.add(finding, reason=reason)
    
    return baseline
