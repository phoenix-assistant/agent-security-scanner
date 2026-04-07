"""
Example secure agent code for testing.
This file demonstrates safe patterns that should NOT trigger findings.
"""

from langchain.agents import AgentExecutor, create_react_agent
from langchain.prompts import ChatPromptTemplate
from langchain.tools import tool, BaseTool
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from typing import Type
import e2b  # Sandbox indicator


# Safe prompt - user input in user message, not system prompt
def safe_prompt_pattern():
    """User input is properly separated from system instructions."""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant. Follow these rules strictly."),
        ("human", "{user_input}"),  # User input as a variable, not interpolated
    ])
    
    return prompt


# Safe tool with Pydantic validation
class FileReadInput(BaseModel):
    """Input schema for file reading tool."""
    
    filename: str = Field(
        description="The filename to read",
        pattern=r'^[a-zA-Z0-9_\-\.]+$'  # Only safe characters
    )


class SafeFileReadTool(BaseTool):
    """A file reading tool with proper input validation."""
    
    name: str = "safe_file_read"
    description: str = "Read a file safely with validation"
    args_schema: Type[BaseModel] = FileReadInput  # Has schema!
    
    def _run(self, filename: str) -> str:
        # Additional runtime validation
        if ".." in filename or filename.startswith("/"):
            raise ValueError("Invalid filename")
        
        allowed_dir = "/safe/directory"
        full_path = f"{allowed_dir}/{filename}"
        
        with open(full_path) as f:
            return f.read()


# Safe tool with @tool decorator and validation
@tool
def safe_search_tool(query: str) -> str:
    """Search for information with validated input.
    
    Args:
        query: The search query (alphanumeric only)
    """
    # Validation at the start
    if not isinstance(query, str):
        raise TypeError("Query must be a string")
    
    if len(query) > 100:
        raise ValueError("Query too long")
    
    # Sanitize
    clean_query = query.strip()[:100]
    
    return f"Results for: {clean_query}"


# Safe code execution with E2B sandbox
def safe_code_execution_with_sandbox():
    """Code execution properly sandboxed with E2B."""
    
    # Uses E2B for sandboxed execution
    sandbox = e2b.Sandbox()
    
    def run_code(code: str) -> str:
        # Runs in isolated E2B sandbox, not on host
        result = sandbox.run_python(code)
        return result.stdout
    
    return run_code


# Safe agent with minimal, appropriate tools
def safe_minimal_agent():
    """Agent with minimal, task-appropriate tools."""
    
    llm = ChatOpenAI()
    
    # Only the tools needed for the specific task
    tools = [
        safe_search_tool,
        SafeFileReadTool(),
    ]
    
    # No code execution, no network, no shell
    agent = create_react_agent(llm, tools, prompt=None)
    executor = AgentExecutor(
        agent=agent, 
        tools=tools,
        max_iterations=5,  # Limited iterations
        verbose=True,  # Logging enabled
    )
    
    return executor


# Safe tool output validation
def safe_tool_chain_with_validation():
    """Tool outputs are validated before being used."""
    
    from pydantic import BaseModel
    
    class SearchResult(BaseModel):
        title: str
        content: str
        source: str
    
    @tool
    def search_tool(query: str) -> str:
        return '{"title": "Result", "content": "...", "source": "wiki"}'
    
    @tool
    def summarize_tool(text: str) -> str:
        return "Summary"
    
    # Get search result
    raw_result = search_tool.run("query")
    
    # SAFE: Validate before using
    validated = SearchResult.model_validate_json(raw_result)
    
    # Now safe to pass to next tool
    summary = summarize_tool.run(validated.content)
    
    return summary
