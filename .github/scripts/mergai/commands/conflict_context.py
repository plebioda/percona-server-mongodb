import click

from git_utils import get_conflict_metadata
from jinja2 import Template

TEMPLATE ="""

# Merge Conflict Resolution Prompt

You are helping to resolve merge conflicts in a Git repository. Below are the conflicts that need to be resolved.

baseline commit: {{ context.base_commit.hexsha }}
our commit: {{ context.ours_commit.hexsha }}
their commit: {{ context.theirs_commit.hexsha }}

{% for path, conflict_data in context.diffs.items() %}
## Conflict in `{{ path }}`

Hunk:

```diff
{{ conflict_data }}
```

{% endfor %}

Please provide a resolution that:
- Incorporates the best aspects of both changes
- Maintains code quality and consistency
- Follows the project's coding standards
- Does not make any changes to the file that are not related to the conflict

Please resolve the conflicts and provide the final merged version of each file.
Please provide an explanation of the changes you made to each file in an output markdown file named `solution.md`.

"""

def write_to_file(filename: str, content: str):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

@click.command()
@click.pass_context
@click.option("--output-prompt-file", default="merge_prompt.md", help="File to write the generated prompt to.")
def conflict_context(ctx, output_prompt_file):

    metadata = get_conflict_metadata()
    import json
    print(json.dumps(metadata, default=str, indent=2))
    if len(metadata["diffs"]) == 0:
        click.echo("No conflicts found")
        exit(1)

    template = Template(TEMPLATE)
    prompt = template.render(context=metadata)
    write_to_file(ctx.params["output_prompt_file"], prompt)
