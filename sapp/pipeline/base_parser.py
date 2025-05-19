# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

"""Abstract Parser for Zoncolan like output"""

import json
import logging
import pprint
from collections import defaultdict
from pathlib import Path
from typing import (
    Any,
    cast,
    Dict,
    Iterable,
    List,
    NamedTuple,
    Set,
    TextIO,
    Tuple,
    Union,
)

import xxhash

from ..analysis_output import AnalysisOutput, Metadata
from ..metrics_logger import ScopedMetricsLogger
from . import (
    DictEntries,
    DictKey,
    Optional,
    ParseConditionTuple,
    ParseIssueTuple,
    ParseType,
    PipelineStep,
    Summary,
)

log: logging.Logger = logging.getLogger("sapp")


# The callable's json output can be found at the given sharded file and offset.
# Used for debugging.
class EntryPosition(NamedTuple):
    callable: str
    shard: int
    offset: int


# pyre-ignore[2]
# pyre-ignore[3]
def log_trace_keyerror(func):
    # pyre-ignore[2]
    # pyre-ignore[3]
    # pyre-ignore[53]
    def wrapper(self, json, *args):
        try:
            return func(self, json, *args)
        except KeyError:
            # The most common problem with parsing json is not finding
            # a field you expect, so we'll catch those and log them, but move
            # on.
            log.exception(
                "Unable to parse trace for the following:\n%s", pprint.pformat(json)
            )
            return ([], {})

    return wrapper


# pyre-ignore[2]
# pyre-ignore[3]
def log_trace_keyerror_in_generator(func):
    # pyre-ignore[2]
    # pyre-ignore[3]
    # pyre-ignore[53]
    def wrapper(self, json, *args):
        try:
            yield from func(self, json, *args)
        except KeyError:
            # The most common problem with parsing json is not finding
            # a field you expect, so we'll catch those and log them, but move
            # on.
            log.exception(
                "Unable to parse trace for the following:\n%s", pprint.pformat(json)
            )
            return
            yield

    return wrapper


class BaseParser(PipelineStep[AnalysisOutput, DictEntries]):
    """The parser takes a json file as input, and provides a simplified output
    for the Processor.
    """

    def __init__(self, repo_dirs: Optional[Set[str]] = None) -> None:
        """
        repo_dirs: Possible absolute paths analyzed during the run. This is used
        to relativize paths in the input. These paths are NOT guaranteed to exist
        on the current machine disk!
        """
        self.repo_dirs: Set[str] = repo_dirs or set()

    def initialize(self, metadata: Optional[Metadata]) -> None:
        return

    # @abstractmethod
    def parse(
        self, input: AnalysisOutput
    ) -> Iterable[Union[ParseConditionTuple, ParseIssueTuple]]:
        """Must return objects with a 'type': ParseType field."""
        raise NotImplementedError("Abstract method called!")

    # @abstractmethod
    def parse_handle(
        self, handle: TextIO
    ) -> Iterable[Union[ParseConditionTuple, ParseIssueTuple]]:
        """Must return objects with a 'type': ParseType field."""
        raise NotImplementedError("Abstract method called!")

    def _analysis_output_to_parsed_tuples(
        self, input: AnalysisOutput
    ) -> Iterable[
        Tuple[ParseType, DictKey, Union[ParseConditionTuple, ParseIssueTuple]]
    ]:
        entries = self.parse(input)

        for e in entries:
            # Parsers may return duck types, but we need a real
            # tools.sapp.sapp.pipeline.ParseType for identity comparisons to work.
            typ = ParseType(e.type)

            key = e.get_key()
            yield typ, key, e

    def analysis_output_to_dict_entries(
        self,
        inputfile: AnalysisOutput,
        previous_issue_handles: Optional[Path],
        linemapfile: Optional[str],
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> DictEntries:
        """Here we take input generators and return a dict with issues,
        preconditions, and postconditions separated. If there is only a single
        generator file, it's simple. If we also pass in a generator from a
        previous inputfile then there are a couple extra steps:

        1. If an issue was seen in the previous inputfile then we won't return
        it, because it's not new.
        2. In addition, we take an optional linemap file that maps for each
        filename, each new file line position to a list of old file line
        position. This is used to adjust handles to we can recognize when issues
        moved.
        """

        issues: List[ParseIssueTuple] = []
        previous_handles: Set[str] = set()
        conditions: Dict[ParseType, Dict[DictKey, List[ParseConditionTuple]]] = {
            ParseType.PRECONDITION: defaultdict(list),
            ParseType.POSTCONDITION: defaultdict(list),
        }

        # If we have a mapfile, create the map.
        if linemapfile:
            log.info("Parsing linemap file")
            with open(linemapfile, "r") as f:
                linemap = json.load(f)
        else:
            linemap = None

        # Save entry info from the parent analysis, if there is one.
        if previous_issue_handles:
            log.info("Parsing previous issue handles")
            previous_handles = BaseParser.parse_handles_file(previous_issue_handles)

        log.info("Parsing analysis output...")
        parsed_issues = 0
        parsed_frames = 0
        for typ, key, e in self._analysis_output_to_parsed_tuples(inputfile):
            if typ == ParseType.ISSUE:
                parsed_issues += 1
                e = cast(ParseIssueTuple, e)
                # We are only interested in issues that weren't in the previous
                # analysis.
                if not self._is_existing_issue(linemap, previous_handles, e, key):
                    issues.append(e.interned())

            elif typ == ParseType.PRECONDITION or typ == ParseType.POSTCONDITION:
                parsed_frames += 1
                e = cast(ParseConditionTuple, e)
                conditions[typ][key].append(e.interned())

            else:
                raise Exception(f"Unhandled type: {typ}")

        scoped_metrics_logger.add_data("parsed_issues", str(parsed_issues))
        scoped_metrics_logger.add_data("parsed_frames", str(parsed_frames))
        scoped_metrics_logger.add_data("new_issues", str(len(issues)))

        return DictEntries(
            issues=issues,
            preconditions=conditions[ParseType.PRECONDITION],
            postconditions=conditions[ParseType.POSTCONDITION],
        )

    def _is_existing_issue(
        self,
        linemap: Dict[str, Any],
        old_handles: Set[str],
        new_issue: ParseIssueTuple,
        new_handle: DictKey,
    ) -> bool:
        if new_handle in old_handles:
            return True
        if not linemap:
            return False
        filename = new_issue.filename
        old_map = linemap.get(filename, {})
        old_lines = old_map.get(str(new_issue.line), [])
        # Once this works, we should remove the "relative" line from the handle
        # and use the absolute one to avoid having to map both the start of the
        # method and the line in the method.

        # Consider all possible old lines
        for old_line in old_lines:
            old_handle = BaseParser.compute_diff_handle(
                filename, old_line, new_issue.code
            )
            if old_handle in old_handles:
                return True
        return False

    def run(
        self,
        input: AnalysisOutput,
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[DictEntries, Summary]:
        return (
            self.analysis_output_to_dict_entries(
                input,
                summary.previous_issue_handles,
                summary.old_linemap_file,
                scoped_metrics_logger,
            ),
            summary,
        )

    @staticmethod
    def compute_master_handle(
        callable: str, line: int, start: int, end: int, code: int
    ) -> str:
        key = "{callable}:{line}|{start}|{end}:{code}".format(
            callable=callable, line=line, start=start, end=end, code=code
        )
        return BaseParser.compute_handle_from_key(key)

    @staticmethod
    def compute_diff_handle(filename: str, old_line: int, code: int) -> str:
        """Uses the absolute line and ignores the callable/character offsets.
        Used only in determining whether new issues are old issues.
        """
        key = "{filename}:{old_line}:{code}".format(
            filename=filename, old_line=old_line, code=code
        )
        return BaseParser.compute_handle_from_key(key)

    @staticmethod
    def compute_handle_from_key(key: str) -> str:
        hash_gen = xxhash.xxh64()
        hash_gen.update(key.encode())
        hash_ = hash_gen.hexdigest()
        return key[: 255 - len(hash_) - 1] + ":" + hash_

    @staticmethod
    def is_supported(metadata: Metadata) -> bool:
        raise NotImplementedError("Subclasses should implement this!")

    @staticmethod
    def parse_handles_file(path: Path) -> Set[str]:
        with open(path) as f:
            lines = (line.rstrip("\n") for line in f)
            return set(filter(lambda line: not line.startswith("#"), lines))

    @staticmethod
    def parse_issue_callable_allowlist_file(path: Path) -> Set[str]:
        with open(path) as f:
            return {line.rstrip("\n") for line in f}

    # Instead of returning the actual json from the AnalysisOutput, we return
    # location information so it can be retrieved later.
    def get_json_file_offsets(self, input: AnalysisOutput) -> Iterable[EntryPosition]:
        raise NotImplementedError("get_json_file_offset not implemented")

    # Given a path and an offset, return the json in mostly-raw form.
    def get_json_from_file_offset(
        self, path: str, offset: int
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError("get_json_from_file_offset not implemented")
