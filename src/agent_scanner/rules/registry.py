"""
Plugin registry for custom security rules.

Allows users to register their own rules via decorator or programmatic API.
"""

from __future__ import annotations

from typing import Type, Callable, Dict, List, Optional
from functools import wraps
import importlib
import importlib.util
import sys
from pathlib import Path

from agent_scanner.rules.base import Rule


class RuleRegistry:
    """
    Global registry for security rules.
    
    Supports:
    - Built-in rules (loaded automatically)
    - Plugin rules via @register_rule decorator
    - Dynamic loading from Python files
    - Rule filtering by ID, severity, tags
    """
    
    _instance: Optional["RuleRegistry"] = None
    
    def __new__(cls) -> "RuleRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._rules: Dict[str, Type[Rule]] = {}
            cls._instance._initialized = False
        return cls._instance
    
    @classmethod
    def get_instance(cls) -> "RuleRegistry":
        """Get the singleton registry instance."""
        return cls()
    
    def register(self, rule_class: Type[Rule]) -> Type[Rule]:
        """
        Register a rule class.
        
        Args:
            rule_class: The rule class to register
            
        Returns:
            The same rule class (for use as decorator)
        """
        if not hasattr(rule_class, 'id'):
            raise ValueError(f"Rule {rule_class.__name__} must have an 'id' attribute")
        
        rule_id = rule_class.id
        if rule_id in self._rules:
            # Allow re-registration (for testing/hot-reload)
            pass
        
        self._rules[rule_id] = rule_class
        return rule_class
    
    def unregister(self, rule_id: str) -> bool:
        """
        Unregister a rule by ID.
        
        Args:
            rule_id: The rule ID to remove
            
        Returns:
            True if removed, False if not found
        """
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False
    
    def get_rule(self, rule_id: str) -> Optional[Type[Rule]]:
        """Get a rule class by ID."""
        return self._rules.get(rule_id)
    
    def get_all_rules(self) -> List[Type[Rule]]:
        """Get all registered rule classes."""
        self._ensure_initialized()
        return list(self._rules.values())
    
    def get_rule_ids(self) -> List[str]:
        """Get all registered rule IDs."""
        self._ensure_initialized()
        return list(self._rules.keys())
    
    def create_instances(
        self,
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Rule]:
        """
        Create instances of registered rules.
        
        Args:
            include: Only include these rule IDs (None = all)
            exclude: Exclude these rule IDs
            
        Returns:
            List of rule instances
        """
        self._ensure_initialized()
        
        instances = []
        for rule_id, rule_class in self._rules.items():
            if include is not None and rule_id not in include:
                continue
            if exclude is not None and rule_id in exclude:
                continue
            
            try:
                instances.append(rule_class())
            except Exception as e:
                # Log but don't fail - bad plugins shouldn't break everything
                print(f"Warning: Could not instantiate rule {rule_id}: {e}")
        
        return instances
    
    def load_plugin_file(self, path: Path) -> List[str]:
        """
        Load rules from a Python file.
        
        Args:
            path: Path to the Python file
            
        Returns:
            List of rule IDs that were loaded
        """
        spec = importlib.util.spec_from_file_location(
            f"agent_scanner_plugin_{path.stem}",
            path
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load plugin from {path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        
        # Track rules before and after
        before = set(self._rules.keys())
        spec.loader.exec_module(module)
        after = set(self._rules.keys())
        
        return list(after - before)
    
    def load_plugin_directory(self, directory: Path) -> List[str]:
        """
        Load all rules from Python files in a directory.
        
        Args:
            directory: Directory containing plugin files
            
        Returns:
            List of all rule IDs that were loaded
        """
        loaded = []
        for path in directory.glob("*.py"):
            if path.name.startswith("_"):
                continue
            try:
                loaded.extend(self.load_plugin_file(path))
            except Exception as e:
                print(f"Warning: Could not load plugin {path}: {e}")
        return loaded
    
    def _ensure_initialized(self):
        """Load built-in rules if not already done."""
        if self._initialized:
            return
        
        self._initialized = True
        
        # Import built-in rules to trigger registration
        try:
            from agent_scanner.rules import owasp
            from agent_scanner.rules import secrets
        except ImportError:
            pass
        
        # Also load the original rules
        try:
            from agent_scanner.rules.prompt_injection import PromptInjectionRule
            from agent_scanner.rules.tool_validation import (
                ToolOutputValidationRule,
                ToolInputValidationRule,
            )
            from agent_scanner.rules.sandbox import MissingSandboxRule
            from agent_scanner.rules.permissions import OverPermissionedRule
            
            self.register(PromptInjectionRule)
            self.register(ToolOutputValidationRule)
            self.register(ToolInputValidationRule)
            self.register(MissingSandboxRule)
            self.register(OverPermissionedRule)
        except ImportError:
            pass
    
    def clear(self):
        """Clear all registered rules (for testing)."""
        self._rules.clear()
        self._initialized = False


# Global registry instance
_registry = RuleRegistry.get_instance()


def register_rule(cls: Type[Rule]) -> Type[Rule]:
    """
    Decorator to register a rule class.
    
    Usage:
        @register_rule
        class MyCustomRule(Rule):
            id = "CUSTOM-001"
            ...
    """
    return _registry.register(cls)


def get_registry() -> RuleRegistry:
    """Get the global rule registry."""
    return _registry
