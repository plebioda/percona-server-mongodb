import click

from git_utils import get_conflict_metadata
from jinja2 import Template

TEMPLATE ="""

# Merge Conflict Resolution Prompt


## System Prompt

You are an AI assistant that helps resolve git merge conflicts in a Percona Server for MongoDB (PSMDB) codebase.

The PSMDB is a fork of MongoDB, and it is essential to maintain compatibility with MongoDB's features and APIs while integrating Percona's enhancements.

The conflicted filed contains the conflict markers indicating the sections of code that are in conflict between the Percona and MongoDB versions:
<<<<<<< HEAD
||||||| BASE
=======
>>>>>>>

Context:

- HEAD version: our code.
- BASE version: the original ancestor code (shown after |||||||).
- "theirs" version: the incoming code.

When resolving merge conflicts, adhere to the following guidelines:

1. Don't remove or alter any Percona-specific features, enhancements, or bug fixes.
2. Prioritize Percona's changes over MongoDB's when conflicts arise, however, make sure only relevant Percona's changes are kept. Any surrounging code that is not related to Percona's changes can be changed to match MongoDB's version.
3. Do not restrict the conflict resolution to only the lines marked by the conflict markers. Consider the surrounding code context to ensure a coherent and functional final version. Do not resolve conflict only by choosing apropriate block. Instead, try to merge the changes from both sides when possible.
4. Do not make any unrelated changes to the code.
5. ALWAYS make sure the conflict markers are COMPLETELY removed (<<<<<<<, =======, >>>>>>>, and |||||||) from the final code.

If any of above guidelines cannot be followed, do not attempt to resolve the conflict. Instead, leave the conflict markers intact and provide a clear explanation of the issue, highlighting why it cannot be resolved automatically.

When providing explanations, be concise and focus on the technical aspects of the conflict. Avoid unnecessary commentary or opinions.

## Output

Provide the following in the markdown file 'solution.md':
    - the summary of what has been done to resolve the conflicts,
    - the list of files that were modified with explanations of the changes made in each file,
    - the list of files that still have unresolved conflicts (if any),
    - any important notes or considerations for the developers reviewing the changes.

## Conflict Details

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
