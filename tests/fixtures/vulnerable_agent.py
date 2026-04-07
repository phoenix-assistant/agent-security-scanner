"""
Example vulnerable agent code for testing.
This file contains intentionally insecure patterns.
"""

from langchain.agents import AgentExecutor, create_react_agent
from langchain.prompts import ChatPromptTemplate
from langchain.tools import tool, PythonREPLTool
from langchain_openai import ChatOpenAI


# ASS-001: Prompt Injection - user input in prompt
def vulnerable_prompt_injection():
    user_input = input("Enter your question: ")
    
    # VULNERABLE: Direct interpolation of user input into system prompt
    prompt = ChatPromptTemplate.from_messages([
        ("system", f"You are a helpful assistant. The user said: {user_input}"),
        ("human", "{input}"),
    ])
    
    return prompt


# ASS-001: Prompt Injection - request data in prompt (Flask pattern)
def vulnerable_flask_prompt(request):
    user_query = request.form["query"]
    
    # VULNERABLE: Web request data in prompt
    prompt = ChatPromptTemplate.from_template(
        f"Answer this question: {user_query}"
    )
    
    return prompt


# ASS-002: Unvalidated Tool Output
def vulnerable_tool_chain():
    @tool
    def search_tool(query: str) -> str:
        """Search for information."""
        return "search result"
    
    @tool
    def summarize_tool(text: str) -> str:
        """Summarize text."""
        return "summary"
    
    # VULNERABLE: Output of search passed directly to summarize without validation
    search_result = search_tool.run("some query")
    summary = summarize_tool.run(search_result)  # Unvalidated!
    
    return summary


# ASS-003: Tool without input validation
@tool
def vulnerable_file_tool(filename: str) -> str:
    """Read a file.
    
    Args:
        filename: Path to the file to read
    """
    # VULNERABLE: No validation of filename parameter
    # Could be path traversal: ../../../etc/passwd
    with open(filename) as f:
        return f.read()


# ASS-004: Code execution without sandbox
def vulnerable_code_execution():
    llm = ChatOpenAI()
    
    # VULNERABLE: Python REPL without sandbox
    repl = PythonREPLTool()
    
    # Even worse - direct exec
    user_code = input("Enter Python code: ")
    exec(user_code)  # CRITICAL: Arbitrary code execution
    
    return repl


# ASS-004: Shell execution without sandbox
def vulnerable_shell_execution():
    import subprocess
    
    command = input("Enter command: ")
    # VULNERABLE: Direct shell execution
    result = subprocess.run(command, shell=True, capture_output=True)
    
    return result


# ASS-005: Over-permissioned agent
def vulnerable_overpermissioned_agent():
    from langchain.tools import (
        PythonREPLTool,
        ShellTool,
        RequestsTool,
        WriteFileTool,
        DeleteFileTool,
    )
    
    llm = ChatOpenAI()
    
    # VULNERABLE: Agent has code exec, shell, network, and file access
    # This is a dangerous combination
    tools = [
        PythonREPLTool(),
        ShellTool(),
        RequestsTool(),
        WriteFileTool(),
        DeleteFileTool(),
    ]
    
    agent = create_react_agent(llm, tools, prompt=None)
    executor = AgentExecutor(agent=agent, tools=tools)
    
    return executor


# Safe pattern for comparison
def safe_prompt_with_validation():
    """Example of a safer pattern."""
    import re
    
    user_input = input("Enter your question: ")
    
    # SAFE: Input validation
    if not re.match(r'^[a-zA-Z0-9\s\?\.\,]+$', user_input):
        raise ValueError("Invalid input")
    
    # SAFE: User input goes in user message, not system prompt
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant."),
        ("human", "{user_question}"),
    ])
    
    return prompt
