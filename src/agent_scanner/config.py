"""
Configuration management for agent-scanner.

Loads configuration from .agent-scan.yaml or pyproject.toml.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
        HAS_TOML = True
    except ImportError:
        HAS_TOML = False


@dataclass
class ScanConfig:
    """Configuration for a scan."""
    
    # Paths
    include: List[str] = field(default_factory=lambda: ["**/*.py"])
    exclude: List[str] = field(default_factory=lambda: [
        "**/node_modules/**",
        "**/.venv/**",
        "**/venv/**",
        "**/__pycache__/**",
        "**/.git/**",
        "**/dist/**",
        "**/build/**",
    ])
    
    # Rules
    enabled_rules: Optional[List[str]] = None  # None = all
    disabled_rules: List[str] = field(default_factory=list)
    
    # Severity thresholds
    fail_on: str = "high"  # critical, high, medium, low, none
    
    # Output
    output_format: str = "console"  # console, sarif, json, html
    output_file: Optional[str] = None
    verbose: bool = False
    no_color: bool = False
    
    # Baseline
    baseline_file: Optional[str] = None
    
    # Plugin paths
    plugin_dirs: List[str] = field(default_factory=list)
    
    # Per-rule configuration
    rule_config: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    @classmethod
    def load(cls, directory: Path = Path(".")) -> "ScanConfig":
        """
        Load configuration from directory.
        
        Looks for (in order):
        1. .agent-scan.yaml / .agent-scan.yml
        2. pyproject.toml [tool.agent-scan]
        3. Defaults
        """
        config = cls()
        
        # Try .agent-scan.yaml
        yaml_paths = [
            directory / ".agent-scan.yaml",
            directory / ".agent-scan.yml",
            directory / "agent-scan.yaml",
        ]
        
        for yaml_path in yaml_paths:
            if yaml_path.exists():
                config = cls._load_yaml(yaml_path)
                break
        else:
            # Try pyproject.toml
            pyproject = directory / "pyproject.toml"
            if pyproject.exists():
                config = cls._load_pyproject(pyproject)
        
        return config
    
    @classmethod
    def _load_yaml(cls, path: Path) -> "ScanConfig":
        """Load configuration from YAML file."""
        if not HAS_YAML:
            print(f"Warning: PyYAML not installed, cannot load {path}")
            return cls()
        
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        
        return cls._from_dict(data)
    
    @classmethod
    def _load_pyproject(cls, path: Path) -> "ScanConfig":
        """Load configuration from pyproject.toml."""
        if not HAS_TOML:
            return cls()
        
        with open(path, "rb") as f:
            data = tomllib.load(f)
        
        tool_config = data.get("tool", {}).get("agent-scan", {})
        return cls._from_dict(tool_config)
    
    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "ScanConfig":
        """Create config from dictionary."""
        config = cls()
        
        if "include" in data:
            config.include = data["include"]
        if "exclude" in data:
            config.exclude = data["exclude"]
        if "enabled_rules" in data:
            config.enabled_rules = data["enabled_rules"]
        if "disabled_rules" in data:
            config.disabled_rules = data["disabled_rules"]
        if "fail_on" in data:
            config.fail_on = data["fail_on"]
        if "output_format" in data:
            config.output_format = data["output_format"]
        if "output_file" in data:
            config.output_file = data["output_file"]
        if "verbose" in data:
            config.verbose = data["verbose"]
        if "no_color" in data:
            config.no_color = data["no_color"]
        if "baseline" in data:
            config.baseline_file = data["baseline"]
        if "plugins" in data:
            config.plugin_dirs = data["plugins"]
        if "rules" in data:
            config.rule_config = data["rules"]
        
        return config
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "include": self.include,
            "exclude": self.exclude,
            "enabled_rules": self.enabled_rules,
            "disabled_rules": self.disabled_rules,
            "fail_on": self.fail_on,
            "output_format": self.output_format,
            "output_file": self.output_file,
            "verbose": self.verbose,
            "no_color": self.no_color,
            "baseline": self.baseline_file,
            "plugins": self.plugin_dirs,
            "rules": self.rule_config,
        }
    
    def save_yaml(self, path: Path) -> None:
        """Save configuration to YAML file."""
        if not HAS_YAML:
            raise ImportError("PyYAML required to save config")
        
        with open(path, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)


def get_default_config_template() -> str:
    """Get a template configuration file."""
    return '''# Agent Security Scanner Configuration
# https://github.com/phoenix-assistant/agent-security-scanner

# File patterns to scan
include:
  - "**/*.py"

# File patterns to exclude
exclude:
  - "**/node_modules/**"
  - "**/.venv/**"
  - "**/venv/**"
  - "**/__pycache__/**"
  - "**/.git/**"

# Rules to disable (by ID)
disabled_rules: []
  # - "LLM01-A"  # Disable prompt injection detection

# Fail if findings at or above this severity
# Options: critical, high, medium, low, none
fail_on: high

# Output format: console, sarif, json, html
output_format: console

# Baseline file for suppressing known issues
# baseline: .agent-scan-baseline.json

# Custom plugin directories
# plugins:
#   - ./custom-rules/

# Per-rule configuration
# rules:
#   LLM01-A:
#     enabled: true
#     severity_override: critical
'''
