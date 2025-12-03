import click
import os

from dotenv import load_dotenv

load_dotenv()

def register_commands(cli):
    from commands.conflict_context import conflict_context
    cli.add_command(conflict_context)

    from commands.resolve import resolve
    cli.add_command(resolve)

@click.group()
@click.pass_context
def cli(ctx):
    ctx.ensure_object(dict)

if __name__ == "__main__":
    register_commands(cli)
    cli()