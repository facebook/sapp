# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

# This file provides a command for viewing the original json output associated
# with callables. Almost every design choice made here was to find a balance of
# efficiency. It can make things a bit confusing, so here is a basic
# explanation of the steps involved.
#
# When we are given a list of callables, we first see if LOOKUP_TABLE has
# already been created. If not, we have to generate it.  ZoncolanParser provides
# a shard number and file offset when parsing each json entry We create an
# instance of LookupTable, which is primarily a mapping from callables to a list
# of shard nummbers and file offsets.  We pickle and compress this file, saving
# it into LOOKUP_TABLE.  The next time someone runs the command, LOOKUP_TABLE
# will be loaded from disk and re-used.
#
# It still takes a good 10s or so to load and decompress the lookup table from
# ramfs. This is a little annoying. In the short term, likely I will provide an
# 'interactive' version where you can keep feeding callables into the script,
# without having to re-load.  We could make this file much smaller by storing
# the hashes of callables instead of the callables themselves, but that will
# stop us from being able to support things like substring matching.

from typing import List

import click

from .analysis_output import AnalysisOutput
from .context import Context, pass_context
from .json_diagnostics import JSONDiagnostics, JSONDiagnosticsException


@click.command(name="json")
@pass_context
@click.option("--force", "-f", is_flag=True, help="Force re-generation of lookup table")
@click.argument("analysis_dir", type=click.Path(exists=True, file_okay=False))
@click.argument("callables", nargs=-1, type=str, required=True)
def json_cmd(
    ctx: Context, force: bool, analysis_dir: str, callables: List[str]
) -> None:
    """Show the original json for the given callables"""

    diagnostics = JSONDiagnostics(
        AnalysisOutput.from_directory(analysis_dir), ctx.parser_class
    )

    try:
        diagnostics.load(force)
    except JSONDiagnosticsException as e:
        raise click.FileError(e.file, e.description)

    output = []
    for callable in callables:
        entries = diagnostics.entries(callable, pretty_print=True)
        if len(entries) == 0:
            click.echo(f"Missing json for {callable}", err=True)
            continue

        output.extend(entries)

    if len(output) > 0:
        click.echo_via_pager("".join(output))
