"""
LLM09: Overreliance

Detects patterns where systems over-rely on LLM outputs without:
- Human verification for critical decisions
- Output validation
- Fallback mechanisms
- Confidence thresholds

References:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- CWE-754: Improper Check for Unusual or Exceptional Conditions
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Optional

from agent_scanner.core.findings import Finding, Severity
from agent_scanner.rules.base import Rule
from agent_scanner.rules.registry import register_rule

if TYPE_CHECKING:
    from agent_scanner.core.parser import ParsedFile


@register_rule
class OverrelianceRule(Rule):
    """
    LLM09-A: Overreliance on LLM Output
    
    Detects patterns where LLM output is used directly without
    validation or fallback mechanisms.
    """
    
    id = "LLM09-A"
    name = "Overreliance on LLM Output"
    description = "LLM output used without validation or fallback"
    severity = Severity.MEDIUM
    cwe_id = "CWE-754"
    owasp_id = "LLM09"
    
    # LLM output methods
    LLM_METHODS = {
        "invoke", "ainvoke",
        "generate", "agenerate",
        "complete", "acomplete",
        "run", "arun",
        "predict", "apredict",
    }
    
    # Critical operations that shouldn't rely solely on LLM
    CRITICAL_OPS = {
        # Medical
        "diagnose", "diagnosis", "prescribe", "medical",
        # Legal
        "legal_advice", "contract", "lawsuit",
        # Financial
        "invest", "trade", "loan_approve", "credit_decision",
        # Safety
        "safety_check", "hazard", "emergency",
        # Security
        "authenticate", "authorize", "access_decision",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for overreliance patterns."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            # Check for LLM output used directly in critical operations
            if isinstance(node, ast.FunctionDef):
                finding = self._check_critical_function(node, parsed_file)
                if finding:
                    findings.append(finding)
            
            # Check for LLM output without try/except
            if isinstance(node, ast.Assign):
                finding = self._check_unhandled_llm_call(node, parsed_file)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_critical_function(
        self,
        node: ast.FunctionDef,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check if critical function relies solely on LLM."""
        
        # Check if this is a critical operation
        func_lower = node.name.lower()
        is_critical = any(op in func_lower for op in self.CRITICAL_OPS)
        
        if not is_critical:
            return None
        
        # Check if function uses LLM
        has_llm_call = False
        has_validation = False
        has_fallback = False
        
        for child in ast.walk(node):
            # Check for LLM call
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in self.LLM_METHODS:
                        has_llm_call = True
            
            # Check for validation patterns
            if isinstance(child, ast.If):
                has_validation = True
            
            # Check for try/except (fallback)
            if isinstance(child, ast.Try):
                has_fallback = True
        
        if has_llm_call and not (has_validation and has_fallback):
            issues = []
            if not has_validation:
                issues.append("no output validation")
            if not has_fallback:
                issues.append("no fallback mechanism")
            
            return self.create_finding(
                title=f"Critical function '{node.name}' over-relies on LLM",
                description=(
                    f"Function '{node.name}' appears to make critical decisions "
                    f"using LLM output with {' and '.join(issues)}. "
                    "For critical operations, LLM output should be validated "
                    "and have fallback mechanisms."
                ),
                file_path=parsed_file.path,
                line=node.lineno,
                column=node.col_offset,
                fix_suggestion=(
                    "1. Add output validation (format, range, sanity checks)\n"
                    "2. Implement fallback for LLM failures\n"
                    "3. Consider human-in-the-loop for final decision\n"
                    "4. Log LLM decisions for audit trail\n"
                    "5. Use confidence thresholds"
                ),
            )
        
        return None
    
    def _check_unhandled_llm_call(
        self,
        node: ast.Assign,
        parsed_file: "ParsedFile",
    ) -> Optional[Finding]:
        """Check for LLM calls without error handling."""
        
        if not isinstance(node.value, ast.Call):
            return None
        
        func_name = None
        if isinstance(node.value.func, ast.Attribute):
            func_name = node.value.func.attr
        
        if func_name not in self.LLM_METHODS:
            return None
        
        # Check if this is inside a try block
        # Note: This is a simplified check - full implementation would track parent
        
        # For now, flag as low confidence finding
        return self.create_finding(
            title="LLM call may lack error handling",
            description=(
                f"LLM method .{func_name}() called without visible error handling. "
                "LLM calls can fail due to rate limits, timeouts, or service issues. "
                "Systems should handle these gracefully."
            ),
            file_path=parsed_file.path,
            line=node.lineno,
            column=node.col_offset,
            fix_suggestion=(
                "Wrap LLM calls in try/except:\n"
                "  try:\n"
                f"      result = llm.{func_name}(...)\n"
                "  except Exception as e:\n"
                "      result = fallback_response()"
            ),
            confidence=0.4,  # Low confidence - might be handled elsewhere
        )


@register_rule
class MissingHumanInLoopRule(Rule):
    """
    LLM09-B: Missing Human-in-the-Loop
    
    Detects critical automated workflows that should have human oversight.
    """
    
    id = "LLM09-B"
    name = "Missing Human-in-the-Loop"
    description = "Automated workflow lacks human oversight"
    severity = Severity.MEDIUM
    cwe_id = "CWE-657"
    owasp_id = "LLM09"
    
    # Workflow indicators
    WORKFLOW_PATTERNS = {
        "auto_approve", "auto_process", "automated",
        "batch_process", "bulk_action",
        "scheduled_job", "cron_job",
        "pipeline", "workflow",
    }
    
    # Actions that should have human review
    NEEDS_REVIEW = {
        "publish", "deploy", "release",
        "approve", "reject",
        "send", "notify", "email",
        "delete", "archive", "purge",
        "payment", "transfer", "refund",
        "ban", "suspend", "terminate",
    }
    
    def check(self, parsed_file: "ParsedFile") -> list[Finding]:
        """Check for missing human-in-the-loop."""
        findings: list[Finding] = []
        
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.FunctionDef):
                # Check if this is an automated workflow
                if self._is_automated_workflow(node):
                    # Check if it performs actions needing review
                    actions = self._find_review_actions(node)
                    if actions:
                        if not self._has_human_review(node):
                            findings.append(self.create_finding(
                                title=f"Automated workflow '{node.name}' lacks human review",
                                description=(
                                    f"Function '{node.name}' appears to be an automated "
                                    f"workflow that performs: {', '.join(actions)}. "
                                    "These actions typically require human oversight."
                                ),
                                file_path=parsed_file.path,
                                line=node.lineno,
                                column=node.col_offset,
                                fix_suggestion=(
                                    "1. Add approval queue for automated actions\n"
                                    "2. Implement review workflow before execution\n"
                                    "3. Send notifications for human review\n"
                                    "4. Add manual override capability\n"
                                    "5. Log all automated decisions for audit"
                                ),
                            ))
        
        return findings
    
    def _is_automated_workflow(self, node: ast.FunctionDef) -> bool:
        """Check if function is an automated workflow."""
        name_lower = node.name.lower()
        
        # Check function name
        if any(pattern in name_lower for pattern in self.WORKFLOW_PATTERNS):
            return True
        
        # Check decorators for scheduling
        for decorator in node.decorator_list:
            dec_str = ast.dump(decorator).lower()
            if any(kw in dec_str for kw in ["schedule", "cron", "periodic", "celery", "task"]):
                return True
        
        return False
    
    def _find_review_actions(self, node: ast.FunctionDef) -> list[str]:
        """Find actions that need human review."""
        found = []
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = None
                if isinstance(child.func, ast.Name):
                    func_name = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    func_name = child.func.attr
                
                if func_name:
                    func_lower = func_name.lower()
                    for action in self.NEEDS_REVIEW:
                        if action in func_lower:
                            found.append(func_name)
                            break
        
        return list(set(found))
    
    def _has_human_review(self, node: ast.FunctionDef) -> bool:
        """Check if workflow has human review mechanism."""
        review_keywords = {
            "approve", "review", "confirm", "verify",
            "manual", "human", "operator",
            "queue", "pending", "await_approval",
        }
        
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if any(kw in child.id.lower() for kw in review_keywords):
                    return True
            if isinstance(child, ast.Attribute):
                if any(kw in child.attr.lower() for kw in review_keywords):
                    return True
        
        return False
