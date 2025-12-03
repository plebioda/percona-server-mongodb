
from langchain_core.tools import tool
from langchain.agents import create_agent

from typing import Optional


@tool
def read_file(file_path: str, start_line: Optional[int] = None, end_line: Optional[int] = None) -> str:
    """Read a file at a given path from line start to line end (inclusive). If lines is None, read the entire file."""

    print(f"Reading file: {file_path}, lines: {start_line}-{end_line}")

    with open(file_path, "r") as f:
        if start_line is None or end_line is None:
            return f.read()
        content = []
        for current_line_number, line in enumerate(f, start=1):
            if current_line_number < start_line:
                continue
            if current_line_number > end_line:
                break
            content.append(line)
        return "".join(content)

@tool
def write_file(file_path: str, content: str) -> str:
    """Write content to a file at a given path."""
    print(f"Writing file: {file_path}")
    with open(file_path, "w") as f:
        f.write(content)
    return f"File {file_path} written successfully."

def build_agent(system_prompt: str, model: str):
    agent = create_agent(
        model=model,
        tools=[read_file, write_file],
        system_prompt=system_prompt,
        # debug=True,
    )

    return agent

import json
from langchain_core.messages import BaseMessage

def extract_text_from_message(msg: BaseMessage) -> str:
    """Handle both str and Gemini-style list-of-parts content."""
    content = msg.content
    if isinstance(content, str):
        return content

    # Gemini often returns: [{"type": "text", "text": "..."}]
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                parts.append(part.get("text", ""))
        return "".join(parts)

    raise TypeError(f"Unsupported message.content type: {type(content)}")


def strip_code_fences(text: str) -> str:
    """Remove ```json ... ``` or ``` ... ``` fences if present."""
    stripped = text.strip()

    if stripped.startswith("```"):
        # Remove starting ```
        stripped = stripped.lstrip("`")
        # Remove optional 'json' language tag
        if stripped.lower().startswith("json"):
            stripped = stripped[4:]  # len("json") + maybe a space/newline
        # Now remove trailing ```
        if "```" in stripped:
            stripped = stripped.split("```", 1)[0]

    return stripped.strip()


def parse_agent_json(result) -> dict:
    """
    result: whatever you get from agent.invoke(...)
    Returns the parsed dict according to your schema.
    """
    last_msg = result["messages"][-1]
    raw_text = extract_text_from_message(last_msg)
    json_text = strip_code_fences(raw_text)
    return json.loads(json_text)
