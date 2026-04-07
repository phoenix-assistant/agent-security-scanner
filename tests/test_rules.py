"""Tests for security rules."""

import pytest
from pathlib import Path

from agent_scanner.core.scanner import Scanner
from agent_scanner.core.findings import Severity


class TestPromptInjection:
    """Tests for ASS-001: Prompt Injection."""
    
    def test_detects_input_in_fstring_prompt(self):
        """Should detect user input in f-string prompts."""
        code = '''
from langchain.prompts import ChatPromptTemplate

user_input = input("Question: ")
prompt = ChatPromptTemplate.from_template(f"You are helpful. Question: {user_input}")
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        assert any(f.rule_id == "ASS-001" for f in findings)
    
    def test_detects_request_data_in_prompt(self):
        """Should detect Flask request data in prompts."""
        code = '''
from langchain.prompts import ChatPromptTemplate

def handler(request):
    query = request.form["query"]
    prompt = ChatPromptTemplate.from_template(f"Answer: {query}")
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        assert any(f.rule_id == "ASS-001" for f in findings)
    
    def test_safe_prompt_no_finding(self):
        """Should not flag prompts without user input interpolation."""
        code = '''
from langchain.prompts import ChatPromptTemplate

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant."),
    ("human", "{user_input}"),
])
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        # Should not have prompt injection findings
        prompt_injection_findings = [f for f in findings if f.rule_id == "ASS-001"]
        assert len(prompt_injection_findings) == 0


class TestToolValidation:
    """Tests for ASS-002 and ASS-003: Tool validation."""
    
    def test_detects_unvalidated_tool_output(self):
        """Should detect tool output passed directly to another tool."""
        code = '''
from langchain.tools import tool

@tool
def tool_a(x: str) -> str:
    return x

@tool  
def tool_b(x: str) -> str:
    return x

result = tool_a.run("input")
final = tool_b.run(result)  # Unvalidated!
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        assert any(f.rule_id == "ASS-002" for f in findings)
    
    def test_detects_tool_without_validation(self):
        """Should detect @tool functions without input validation."""
        code = '''
from langchain.tools import tool

@tool
def my_tool(filename: str) -> str:
    """Read a file."""
    with open(filename) as f:
        return f.read()
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        assert any(f.rule_id == "ASS-003" for f in findings)
    
    def test_tool_with_validation_no_finding(self):
        """Should not flag tools that have validation."""
        code = '''
from langchain.tools import tool

@tool
def my_tool(filename: str) -> str:
    """Read a file."""
    if not isinstance(filename, str):
        raise TypeError()
    if ".." in filename:
        raise ValueError("Invalid path")
    with open(filename) as f:
        return f.read()
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        # Should not have tool validation findings
        tool_findings = [f for f in findings if f.rule_id == "ASS-003"]
        assert len(tool_findings) == 0


class TestSandbox:
    """Tests for ASS-004: Missing sandbox."""
    
    def test_detects_bare_exec(self):
        """Should detect exec() without sandbox."""
        code = '''
user_code = input("Code: ")
exec(user_code)
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        assert any(f.rule_id == "ASS-004" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)
    
    def test_detects_python_repl_tool(self):
        """Should detect PythonREPLTool without sandbox."""
        code = '''
from langchain.tools import PythonREPLTool

repl = PythonREPLTool()
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        assert any(f.rule_id == "ASS-004" for f in findings)
    
    def test_exec_with_sandbox_indicator(self):
        """Should be less severe when sandbox indicators present."""
        code = '''
import e2b
from e2b_code_interpreter import CodeInterpreter

sandbox = CodeInterpreter()
result = sandbox.run_python(user_code)
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        # Should either have no findings or lower confidence
        critical_findings = [
            f for f in findings 
            if f.rule_id == "ASS-004" and f.confidence > 0.8
        ]
        assert len(critical_findings) == 0


class TestPermissions:
    """Tests for ASS-005: Over-permissioned access."""
    
    def test_detects_many_tools(self):
        """Should detect agents with too many tools."""
        code = '''
from langchain.agents import AgentExecutor

agent = AgentExecutor(
    agent=my_agent,
    tools=[t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12],
)
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        assert any(f.rule_id == "ASS-005" for f in findings)
    
    def test_detects_dangerous_combination(self):
        """Should detect dangerous tool combinations."""
        code = '''
from langchain.agents import create_react_agent
from langchain.tools import PythonREPLTool

tools = [PythonREPLTool(), RequestsTool()]  # Code exec + network
agent = create_react_agent(llm, tools, prompt)
'''
        scanner = Scanner()
        findings = scanner.scan_source(code)
        
        # Should flag the combination
        assert any(
            f.rule_id == "ASS-005" and "combination" in f.title.lower()
            for f in findings
        ) or any(f.rule_id == "ASS-004" for f in findings)


class TestScanner:
    """Tests for the main scanner."""
    
    def test_scan_vulnerable_file(self):
        """Should find issues in the vulnerable fixture."""
        fixture_path = Path(__file__).parent / "fixtures" / "vulnerable_agent.py"
        
        if not fixture_path.exists():
            pytest.skip("Fixture file not found")
        
        scanner = Scanner()
        result = scanner.scan_path(fixture_path)
        
        # Should find multiple issues
        assert len(result.findings) > 0
        assert result.critical_count > 0 or result.high_count > 0
    
    def test_scan_safe_file(self):
        """Should find fewer/no critical issues in safe fixture."""
        fixture_path = Path(__file__).parent / "fixtures" / "safe_agent.py"
        
        if not fixture_path.exists():
            pytest.skip("Fixture file not found")
        
        scanner = Scanner()
        result = scanner.scan_path(fixture_path)
        
        # Should have fewer critical issues
        # Note: May still have some lower-severity findings
        assert result.critical_count == 0


class TestOutput:
    """Tests for output formatters."""
    
    def test_sarif_output(self):
        """Should generate valid SARIF output."""
        from agent_scanner.output.sarif import SarifOutput
        from agent_scanner.core.findings import ScanResult, Finding, Location, Severity
        
        result = ScanResult(
            findings=[
                Finding(
                    rule_id="ASS-001",
                    title="Test Finding",
                    severity=Severity.HIGH,
                    description="Test description",
                    location=Location(file=Path("test.py"), line=10, column=5),
                    fix_suggestion="Fix it",
                )
            ],
            files_scanned=1,
            scan_duration_ms=100,
        )
        
        sarif = SarifOutput()
        output = sarif.generate(result)
        
        assert output["version"] == "2.1.0"
        assert len(output["runs"]) == 1
        assert len(output["runs"][0]["results"]) == 1
    
    def test_json_output(self):
        """Should generate valid JSON output."""
        from agent_scanner.output.json_output import JsonOutput
        from agent_scanner.core.findings import ScanResult, Finding, Location, Severity
        
        result = ScanResult(
            findings=[
                Finding(
                    rule_id="ASS-001",
                    title="Test Finding",
                    severity=Severity.HIGH,
                    description="Test description",
                    location=Location(file=Path("test.py"), line=10, column=5),
                    fix_suggestion="Fix it",
                )
            ],
            files_scanned=1,
            scan_duration_ms=100,
        )
        
        json_out = JsonOutput()
        output = json_out.generate(result)
        
        assert output["summary"]["total_findings"] == 1
        assert output["summary"]["high"] == 1
        assert len(output["findings"]) == 1
