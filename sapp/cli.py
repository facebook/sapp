#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import logging
import os
from typing import Dict, Type

import click

from .cli_lib import commands, common_options
from .context import Context
from .db import DB, DBType
from .lint import lint
from .pipeline.base_parser import BaseParser
from .pipeline.mariana_trench_parser import Parser as MarianaTrenchParser
from .pipeline.pysa_taint_parser import Parser as PysaParser

LOG: logging.Logger = logging.getLogger("sapp")

PARSERS: Dict[str, Type[BaseParser]] = {
    "pysa": PysaParser,
    "mariana-trench": MarianaTrenchParser,
}


@common_options
@click.option(
    "--database-engine",
    "--database",
    type=click.Choice([DBType.SQLITE, DBType.MEMORY]),
    default=DBType.SQLITE,
    help="database engine to use",
)
@click.option(
    "--tool",
    type=click.Choice(list(PARSERS.keys())),
    default="pysa",
    help="tool the data is coming from",
)
@click.pass_context
def cli(
    ctx: click.Context,
    repository: str,
    database_name: str,
    database_engine: str,
    tool: str,
) -> None:
    ctx.obj = Context(
        repository=repository,
        database=DB(
            database_engine, os.path.expanduser(database_name), assertions=True
        ),
        tool=tool,
        parser_class=PARSERS[tool],
    )
    LOG.debug(f"Context: {ctx.obj}")


for command in commands:
    cli.add_command(command)
cli.add_command(lint)

if __name__ == "__main__":
    logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s")
    cli()
