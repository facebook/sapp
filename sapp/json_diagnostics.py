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
# already been created. If not, we have to generate it.  The parser provides
# a shard number and file offset when parsing each json entry. We create an
# instance of LookupTable, which is primarily a mapping from callables to a list
# of shard nummbers and file offsets.  We write this into a file, saving
# it into LOOKUP_TABLE.  The next time someone runs the command, LOOKUP_TABLE
# will be loaded from disk and re-used.
#
# It still takes a good 10s or so to load and decompress the lookup table from
# ramfs. This is a little annoying. In the short term, likely I will provide an
# 'interactive' version where you can keep feeding callables into the script,
# without having to re-load.  We could make this file much smaller by storing
# the hashes of callables instead of the callables themselves, but that will
# stop us from being able to support things like substring matching.

import json
import logging
import os
import sys
from collections import defaultdict
from functools import partial
from multiprocessing import Pool
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple, Type

import zstd
from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments.lexers import JsonLexer

from .analysis_output import AnalysisOutput
from .pipeline.base_parser import BaseParser


logger: logging.Logger = logging.getLogger("sapp")

DEFAULT_LOOKUP_TABLE_PATH = "json_lookup_table.db"
TABLE_VERSION = 2


class JSONDiagnosticsException(Exception):
    __slots__ = ["file", "description"]

    def __init__(self, file: str, description: str) -> None:
        # pyre-fixme[4]: Attribute must be annotated.
        self.file = file
        # pyre-fixme[4]: Attribute must be annotated.
        self.description = description


FileID = int
SummaryPosition = Tuple[FileID, int]
LookupEntries = Dict[str, List[SummaryPosition]]
Metadata = Dict[str, Any]


class LookupTable(NamedTuple):
    version: int = TABLE_VERSION
    file_index: Dict[FileID, str] = {}
    entries: LookupEntries = {}

    def to_json(self) -> str:
        return json.dumps((self.version, self.file_index, self.entries))

    @classmethod
    def from_json(cls, value: str) -> "LookupTable":
        version, file_index, entries = json.loads(value)
        # JSON does not allow integers as object keys
        file_index = {int(index): filename for index, filename in file_index.items()}
        return cls(version=version, file_index=file_index, entries=entries)


def _parse_file(
    parser_class: Type[BaseParser], path: str
) -> Tuple[str, Dict[str, List[int]]]:
    parser = parser_class()

    entries = defaultdict(list)
    with open(path) as handle:
        for position in parser.get_json_file_offsets(
            AnalysisOutput.from_handle(handle)
        ):
            entries[position.callable].append(position.offset)

    return (path, dict(entries))


class JSONDiagnostics(object):
    def __init__(
        self,
        analysis_output: AnalysisOutput,
        parser_class: Type[BaseParser],
        table_path: str = DEFAULT_LOOKUP_TABLE_PATH,
    ) -> None:
        self.analysis_output = analysis_output
        self.lookup_table_path = table_path
        self.lookup_table: Optional[LookupTable] = None
        self.parser_class = parser_class

    def load(self, force_generation: bool = False) -> None:
        self.lookup_table = self._get_lookup_table(force_generation)

    def callables(self) -> Iterable[str]:
        lookup_table = self.lookup_table
        assert lookup_table, "Call load() first"
        return lookup_table.entries.keys()

    def entries(self, search: str, pretty_print: bool = False) -> List[Dict[str, Any]]:
        lookup_table = self.lookup_table
        assert lookup_table, "Call load() first"

        parser = self.parser_class()

        entry_locations = {
            c: lookup_table.entries.get(c, []) for c in self.callables() if search in c
        }

        entries = []
        for callable_name, entry_location in entry_locations.items():
            for (file_id, offset) in entry_location:
                path = lookup_table.file_index[file_id]

                errors = parser.get_json_from_file_offset(path, offset)
                if errors:
                    if pretty_print:
                        entries.append(
                            highlight(
                                json.dumps({callable_name: errors}, indent=2),
                                JsonLexer(),
                                TerminalFormatter(),
                            )
                        )
                    else:
                        entries.append(errors)
                else:
                    logger.warn(f"No json found at {path, offset}")

        return entries

    def _load_lookup_table(self, path: str) -> Optional[LookupTable]:
        logger.info(f"Loading lookup table from `{path}`")

        with open(path, "rb") as fh:
            compressed = fh.read()
        decompressed = zstd.ZstdDecompressor().decompress(compressed)
        table = LookupTable.from_json(decompressed.decode("utf8"))

        if table.version != TABLE_VERSION:
            raise JSONDiagnosticsException(
                path, f"Unexpected file version {table.version}"
            )

        # Check cache validity.
        indexed_files = set(table.file_index.values())
        filenames = set(map(os.path.abspath, self.analysis_output.file_names()))
        if not filenames.issubset(indexed_files):
            logger.info("Lookup table is invalidated, ignoring it.")
            return None

        return table

    def _save_lookup_table(self, path: str, table: LookupTable) -> None:
        logger.info(f"Writing lookup table to `{path}`")
        compressed = zstd.ZstdCompressor(threads=-1).compress(
            table.to_json().encode("utf8")
        )
        tmp_name = path + ".tmp"
        with open(tmp_name, "wb") as fh:
            fh.write(compressed)
        os.rename(tmp_name, path)

    def _generate_lookup_table(self) -> LookupTable:
        logger.info("Generating lookup table")
        filenames = list(map(os.path.abspath, self.analysis_output.file_names()))

        table = LookupTable()

        next_id = 0
        filename_to_id = {}

        entries = {}
        with Pool(processes=None) as pool:
            for i, (filename, entries) in enumerate(
                pool.imap_unordered(partial(_parse_file, self.parser_class), filenames)
            ):
                if sys.stdout.isatty():
                    sys.stdout.write(f"\rProcessed {i+1} out of {len(filenames)} files")
                    sys.stdout.flush()
                if filename not in filename_to_id:
                    filename_to_id[filename] = next_id
                    table.file_index[next_id] = filename
                    next_id += 1
                file_id = filename_to_id[filename]
                entries = {
                    c: [(file_id, offset) for offset in offsets]
                    for c, offsets in entries.items()
                }
                table.entries.update(entries)

        print("")

        return table

    def _get_lookup_table(self, force_generation: bool) -> LookupTable:
        if os.path.exists(self.lookup_table_path) and not force_generation:
            table = self._load_lookup_table(self.lookup_table_path)
            if table is not None:
                return table

        table = self._generate_lookup_table()
        self._save_lookup_table(self.lookup_table_path, table)
        return table
