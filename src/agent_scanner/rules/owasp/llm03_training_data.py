"""
LLM03: Training Data Poisoning

Detects vulnerabilities related to training data manipulation that could
compromise model integrity, introduce biases, or create backdoors.

References:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- CWE-502: Deserialization of Untrusted Data
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
class TrainingDataPoisoningRule(Rule):
    """
    LLM03-A: Training Data Poisoning Risk
    
    Detects patterns that could lead to training data poisoning,
    such as loading training data from untrusted sources.
    """
    
    id = "LLM03-A"
    name = "Training Data Poisoning Risk"
    description = "Training data loaded from potentially untrusted source"
    severity = Severity.HIGH
    cwe_id = "CWE-502"
    owasp_id = "LLM03"
    
    # Training-related function patterns
    TRAINING_FUNCTIONS = {
        "fine_tune", "finetune",
        "train", "fit",
        "train_model", "train_llm",
        "create_fine_tuned_model",
        "prepare_training_data",
        "load_training_data",
    }
    
    # Dataset loading patterns
    DATASET_LOADERS = {
        "load_dataset",  # HuggingFace
        "Dataset.from_json",
        "Dataset.from_csv",
        "Dataset.from_text",
        "DataLoader",
        "TrainingArguments",
        "Trainer",
        "SFTTrainer",  # TRL
        "DPOTrainer",  # TRL
        "PPOTrainer",  # TRL
    }
    
    # Untrusted data sources
    UNTRUSTED_SOURCES = {
        "from_url", "from_web",
        "requests.get", "requests.post",
        "urllib.request",
        "scrape", "crawl",
        "user_input", "user_data",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for training data poisoning risks."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                # Check for training with potentially untrusted data
                finding = self._check_training_call(node, parsed_file)
                if finding:
                    findings.append(finding)
                
                # Check for dataset loading without verification
                finding = self._check_dataset_loading(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_training_call(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check training function calls for poisoning risks."""
        
        func_name = self._get_func_name(node)
        if not func_name:
            return None
        
        func_lower = func_name.lower()
        
        # Check if this is a training function
        is_training = any(t in func_lower for t in self.TRAINING_FUNCTIONS)
        if not is_training:
            return None
        
        # Check if data comes from untrusted source
        for arg in node.args:
            if self._is_untrusted_source(arg):
                return self.create_finding(
                    title=f"Training with potentially untrusted data",
                    description=(
                        f"Function '{func_name}' appears to use training data that may "
                        "come from an untrusted source. Malicious training data can poison "
                        "the model, introducing backdoors or biased behavior."
                    ),
                    file_path=parsed_file.path,
                    line=node.lineno,
                    column=node.col_offset,
                    fix_suggestion=(
                        "1. Verify training data integrity (checksums, signatures)\n"
                        "2. Use curated datasets from trusted sources\n"
                        "3. Implement data validation and filtering\n"
                        "4. Monitor for distribution shifts in training data\n"
                        "5. Use techniques like data sanitization"
                    ),
                )
        
        return None
    
    def _check_dataset_loading(
        self,
        node: ast.Call,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check dataset loading for verification."""
        
        func_name = self._get_func_name(node)
        if not func_name:
            return None
        
        if func_name not in self.DATASET_LOADERS and not func_name.startswith("load"):
            return None
        
        # Check for URL-based loading without verification
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.startswith(("http://", "https://", "ftp://")):
                    return self.create_finding(
                        title=f"Dataset loaded from URL without verification",
                        description=(
                            f"Dataset loaded from '{arg.value[:50]}...' via {func_name}. "
                            "Remote datasets can be modified by attackers to poison training."
                        ),
                        file_path=parsed_file.path,
                        line=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=(
                            "1. Pin specific dataset versions/commits\n"
                            "2. Verify checksums of downloaded data\n"
                            "3. Use signed/authenticated data sources\n"
                            "4. Cache and version control training data locally"
                        ),
                        confidence=0.8,
                    )
        
        return None
    
    def _is_untrusted_source(self, node: ast.AST) -> bool:
        """Check if node represents untrusted data source."""
        if isinstance(node, ast.Call):
            func_name = self._get_func_name(node)
            if func_name:
                return any(u in func_name.lower() for u in self.UNTRUSTED_SOURCES)
        return False
    
    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None


@register_rule
class UnsafeFineTuningRule(Rule):
    """
    LLM03-B: Unsafe Fine-Tuning Patterns
    
    Detects fine-tuning patterns that lack safety measures.
    """
    
    id = "LLM03-B"
    name = "Unsafe Fine-Tuning"
    description = "Fine-tuning lacks safety guardrails"
    severity = Severity.MEDIUM
    cwe_id = "CWE-693"
    owasp_id = "LLM03"
    
    # Fine-tuning APIs
    FINETUNE_APIS = {
        "openai.fine_tuning",
        "openai.FineTuningJob",
        "client.fine_tuning",
        "create_fine_tuned_model",
        "Trainer", "SFTTrainer",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for unsafe fine-tuning patterns."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if not func_name:
                    continue
                
                # Check for fine-tuning without safety measures
                if any(ft in func_name for ft in ["fine_tun", "FineTun", "Trainer"]):
                    # Check for lack of safety configs
                    has_safety = self._check_safety_config(node)
                    if not has_safety:
                        findings.append(self.create_finding(
                            title="Fine-tuning without explicit safety config",
                            description=(
                                f"Fine-tuning via {func_name} detected without visible "
                                "safety configurations. Fine-tuning can remove safety "
                                "training and introduce vulnerabilities."
                            ),
                            file_path=parsed_file.path,
                            line=node.lineno,
                            column=node.col_offset,
                            fix_suggestion=(
                                "1. Include safety-focused training examples\n"
                                "2. Use safety evaluation during training\n"
                                "3. Test fine-tuned model with adversarial prompts\n"
                                "4. Consider Constitutional AI techniques"
                            ),
                            confidence=0.6,
                        ))
        
        return findings
    
    def _check_safety_config(self, node: ast.Call) -> bool:
        """Check if fine-tuning call has safety configurations."""
        for kw in node.keywords:
            if kw.arg and "safety" in kw.arg.lower():
                return True
            if kw.arg and "evaluation" in kw.arg.lower():
                return True
        return False
    
    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
