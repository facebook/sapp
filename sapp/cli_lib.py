# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import logging
import os
import pathlib
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple

import click
import click_log
import IPython
from click import Parameter, Path, argument, option
from traitlets.config import Config

from .analysis_output import AnalysisOutput
from .context import Context, pass_context
from .db import DB
from .extensions import prompt_extension
from .filesystem import find_root
from .models import PrimaryKeyGenerator
from .pipeline import Pipeline
from .pipeline.add_features import AddFeatures
from .pipeline.create_database import CreateDatabase
from .pipeline.database_saver import DatabaseSaver
from .pipeline.model_generator import ModelGenerator
from .pipeline.trim_trace_graph import TrimTraceGraph
from .ui import filters
from .ui.interactive import Interactive
from .ui.server import start_server
from .warning_messages import update_warning_messages

MARKER_DIRECTORIES = [".pyre", ".hg", ".git", ".svn"]

# pyre-fixme[5]: Global expression must be annotated.
logger = logging.getLogger("sapp")


def require_option(current_ctx: click.Context, param_name: str) -> None:
    """Throw an exception if an option wasn't required. This is useful when its
    optional in some contexts but required for a subcommand"""

    ctx = current_ctx
    param_definition = None
    while ctx is not None:
        # ctx.command.params has the actual definition of the param. We use
        # this when raising the exception.
        param_definition = next(
            (p for p in ctx.command.params if p.name == param_name), None
        )

        # ctx.params has the current value of the parameter, as set by the user.
        if ctx.params.get(param_name):
            return
        ctx = ctx.parent

    assert param_definition, f"unknown parameter {param_name}"
    raise click.MissingParameter(ctx=current_ctx, param=param_definition)


# pyre-fixme[3]: Return type must be annotated.
# pyre-fixme[2]: Parameter must be annotated.
def common_options(func):
    @click.group(context_settings={"help_option_names": ["--help", "-h"]})
    @click_log.simple_verbosity_option(logger)
    @option(
        "--repository",
        "-r",
        default=lambda: find_root(MARKER_DIRECTORIES),
        type=Path(exists=True, file_okay=False),
        help="Root of the repository (regardless of the directory analyzed)",
    )
    @option(
        "--database-name",
        "--dbname",
        callback=default_database,
        type=Path(dir_okay=False),
    )
    @wraps(func)
    # pyre-fixme[53]: Captured variable `func` is not annotated.
    # pyre-fixme[3]: Return type must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def default_database(
    ctx: click.Context, _param: Parameter, value: Optional[str]
) -> str:
    """By default, use a database at the current dir"""
    if value:
        return value

    return os.path.join(os.path.curdir, DB.DEFAULT_DB_FILE)


@click.command(
    help="interactive exploration of issues",
    context_settings={"ignore_unknown_options": True},
)
@pass_context
@click.argument("ipython_args", nargs=-1, type=click.UNPROCESSED)
# pyre-fixme[2]: Parameter must be annotated.
def explore(ctx: Context, ipython_args) -> None:
    scope_vars = Interactive(
        database=ctx.database,
        repository_directory=ctx.repository,
        parser_class=ctx.parser_class,
    ).setup()
    config = Config()
    config.InteractiveShellApp.extensions = [
        prompt_extension.__name__
    ] + ctx.ipython_extensions
    config.InteractiveShellApp.profile = "sapp"
    config.InteractiveShellApp.display_banner = False

    config.InteractiveShell.show_rewritten_input = False
    config.InteractiveShell.autocall = 2

    IPython.start_ipython(
        argv=ipython_args if ipython_args else [], user_ns=scope_vars, config=config
    )


@click.command(help="parse static analysis output and save to disk")
@pass_context
@option("--run-kind", type=str)
@option("--branch", type=str)
@option("--commit-hash", type=str)
@option("--job-id", type=str)
@option("--differential-id", type=int)
@option("--add-feature", type=str, multiple=True)
@option(
    "--previous-issue-handles",
    type=Path(exists=True),
    help=("file containing list of issue handles to compare INPUT_FILE to"),
)
@option(
    "--linemap",
    type=Path(exists=True),
    help="json file mapping new locations to old locations",
)
@option(
    "--store-unused-models",
    is_flag=True,
    help="store pre/post conditions unrelated to an issue",
)
@option("--dry-run", is_flag=True)
@argument("input_file", type=Path(exists=True))
def analyze(
    ctx: Context,
    run_kind: Optional[str],
    branch: Optional[str],
    commit_hash: Optional[str],
    job_id: Optional[str],
    differential_id: Optional[int],
    previous_issue_handles: Optional[str],
    linemap: Optional[str],
    store_unused_models: bool,
    dry_run: bool,
    input_file: str,
    add_feature: Optional[List[str]],
) -> None:
    # Store all options in the right places
    summary_blob: Dict[str, Any] = {
        "run_kind": run_kind,
        "repository": ctx.repository,
        "branch": branch,
        "commit_hash": commit_hash,
        "old_linemap_file": linemap,
        "store_unused_models": store_unused_models,
    }

    if job_id is None and differential_id is not None:
        job_id = "user_input_" + str(differential_id)
    summary_blob["job_id"] = job_id

    if previous_issue_handles:
        summary_blob["previous_issue_handles"] = AnalysisOutput.from_file(
            previous_issue_handles
        )

    # Construct pipeline
    if os.path.isdir(input_file):
        analysis_output = AnalysisOutput.from_directory(input_file)
    else:
        analysis_output = AnalysisOutput.from_file(input_file)

    pipeline_steps = [
        ctx.parser_class(),
        CreateDatabase(ctx.database),
        AddFeatures(add_feature),
        ModelGenerator(),
        TrimTraceGraph(),
        DatabaseSaver(ctx.database, PrimaryKeyGenerator(), dry_run),
    ]
    # pyre-fixme[6]: Expected
    #  `List[tools.sapp.sapp.pipeline.PipelineStep[typing.Any, typing.Any]]` for 1st
    #  param but got `List[typing.Union[DatabaseSaver, ModelGenerator, TrimTraceGraph,
    #  tools.sapp.sapp.base_parser.BaseParser]]`.
    pipeline = Pipeline(pipeline_steps)
    pipeline.run(analysis_output, summary_blob)


@click.command(
    help="backend flask server for exploration of issues",
    context_settings={"ignore_unknown_options": True},
)
@option("--debug/--no-debug", default=False, help="Start Flask server in debug mode")
@option(
    "--static-resources", default=None, help="Directory to serve static resources from"
)
# pyre-fixme[56]: Pyre was not able to infer the type of argument `os.getcwd()` to
#  decorator factory `click.option`.
@option(
    "--source-directory", default=os.getcwd(), help="Directory to look for source code"
)
@option(
    "--editor-schema",
    default=None,
    help="Editor schema to open files from a browser, e.g. `vscode:`",
)
@pass_context
def server(
    ctx: Context,
    debug: bool,
    static_resources: Optional[str],
    source_directory: str,
    editor_schema: Optional[str],
) -> None:
    start_server(ctx.database, debug, static_resources, source_directory, editor_schema)


@click.group()
def filter() -> None:
    pass


@filter.command(
    name="import",
    help="Import a filter or a directory containing filters into database",
)
@pass_context
@argument("input_filter_path", type=Path(exists=True, readable=True))
def import_filters(
    ctx: Context,
    input_filter_path: str,
) -> None:
    filters.import_filter_from_path(ctx.database, pathlib.Path(input_filter_path))


@filter.command(
    name="export",
    help="Export a filter from database",
)
@pass_context
@argument("filter_name", type=str)
@option(
    "--output-path",
    "-o",
    type=Path(writable=True),
    help="Path where you want to save the exported filter to",
)
def export_filter(
    ctx: Context,
    filter_name: str,
    output_path: str,
) -> None:
    if output_path:
        filters.export_filter(ctx.database, filter_name, pathlib.Path(output_path))
    else:
        filters.export_filter(ctx.database, filter_name)


@filter.command(name="delete", help="Delete filters from database")
@argument("filter_names", nargs=-1, required=True)
@pass_context
def delete_filters(
    ctx: Context,
    filter_names: Tuple[str],
) -> None:
    filters.delete_filters(ctx.database, filter_names)


@filter.command(
    name="issues",
    help="Show issues after applying a filter or directory of filters to a run",
    context_settings={"token_normalize_func": str.lower},
)
@click.option(
    "--output-format",
    type=click.Choice(["sapp", "sarif"]),
    default="sapp",
    help="output format you want your filtered results in",
)
@argument("run_id", type=int)
@argument("input_filter_path", type=Path(exists=True, readable=True))
@pass_context
def filter_issues(
    ctx: Context,
    run_id: int,
    input_filter_path: str,
    output_format: str,
) -> None:
    """Applies filter from INPUT_FILTER_PATH to filter issues in RUN_ID

    RUN_ID is the `Run` number corresponding to the list of issues you want to apply the filter to
    INPUT_FILTER_PATH is the path to the filter you want to use to filter the list of issues in RUN_ID
    OUTPUT_FORMAT is the format you want the results to be in
    """
    filters.filter_run(ctx, run_id, pathlib.Path(input_filter_path), output_format)


@click.group()
def update() -> None:
    pass


@update.command(
    name="warning-codes",
    help="Parse static analysis metadata output and update warning codes in SAPP db",
)
@argument("input_metadata_file", type=Path(exists=True, readable=True))
@pass_context
def update_warning_codes(
    ctx: Context,
    input_metadata_file: str,
) -> None:
    update_warning_messages(ctx.database, pathlib.Path(input_metadata_file))


commands: List[Callable[[], None]] = [
    analyze,
    explore,
    server,
    filter,
    update,
]
