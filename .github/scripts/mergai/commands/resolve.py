import click
import json
from agent import build_agent, parse_agent_json
from constants import DEFAULT_MODEL, SYSTEM_PROMPT
from langchain_core.messages import HumanMessage
from git_utils import get_conflict_metadata, apply_patch_to_file

@click.command()
@click.pass_context
def resolve(ctx):
    agent = build_agent(SYSTEM_PROMPT, DEFAULT_MODEL)

    conflict_metadata = get_conflict_metadata()

    print(json.dumps(conflict_metadata, default=str, indent=2))

    res = agent.invoke({
        "messages": [
            HumanMessage(content=json.dumps(conflict_metadata, default=str)),
            HumanMessage(content="""Using the above context, resolve the merge conflicts.

IMPORTANT: You MUST:
1. Read each conflicted file using read_file to see the full file content with conflict markers
2. Resolve each conflict by writing the complete resolved file using write_file
3. After writing all resolved files, return a JSON summary with your explanations

Do not return JSON without first writing the files. The files must be written to disk using the write_file tool.""")
        ]
    })

    final_msg = res["messages"][-1].content
    data = parse_agent_json(res)

    print("\nFinal JSON response:")
    print(data)
