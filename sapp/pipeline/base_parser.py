# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Abstract Parser for Zoncolan like output"""

import logging
import pprint
from collections import defaultdict
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    NamedTuple,
    Set,
    TextIO,
    Tuple,
    Union,
    cast,
)

import xxhash

from ..analysis_output import AnalysisOutput, Metadata
from . import (
    DictEntries,
    DictKey,
    Optional,
    ParseCondition,
    ParseConditionTuple,
    ParseIssue,
    ParseIssueTuple,
    ParseType,
    PipelineStep,
    Summary,
)

# if these imports have the same name we get a linter error
try:
    import ujson as json
except ImportError:
    import json  # noqa


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

    def __init__(self, repo_dirs: Optional[List[str]] = None) -> None:
        """
        repo_dirs: Possible absolute paths analyzed during the run. This is used to relativize
        paths in the input. These paths are NOT guaranteed to exist on the current machine disk!
        """
        self.repo_dirs: List[str] = repo_dirs or []

    def initialize(self, metadata: Optional[Metadata]) -> None:
        return

    # @abstractmethod
    def parse(
        self, input: AnalysisOutput
    ) -> Iterable[
        Union[ParseCondition, ParseIssue, ParseConditionTuple, ParseIssueTuple]
    ]:
        """Must return objects with a 'type': ParseType field."""
        raise NotImplementedError("Abstract method called!")

    # @abstractmethod
    def parse_handle(
        self, handle: TextIO
    ) -> Iterable[
        Union[ParseCondition, ParseIssue, ParseConditionTuple, ParseIssueTuple]
    ]:
        """Must return objects with a 'type': ParseType field."""
        raise NotImplementedError("Abstract method called!")

    def _analysis_output_to_parsed_tuples(
        self, input: AnalysisOutput
    ) -> Iterable[
        Tuple[ParseType, DictKey, Union[ParseConditionTuple, ParseIssueTuple]]
    ]:
        entries = self.parse(input)

        for e in entries:
            if isinstance(e, ParseConditionTuple):
                typ = e.type
                key = (e.caller, e.caller_port)
            elif isinstance(e, ParseIssueTuple):
                typ = ParseType.ISSUE
                key = e.handle
            else:
                # legacy raw dicts
                typ = e["type"]
                if typ == ParseType.ISSUE:
                    e = ParseIssueTuple.from_typed_dict(cast(ParseIssue, e))
                    key = e.handle
                elif typ == ParseType.PRECONDITION or typ == ParseType.POSTCONDITION:
                    e = ParseConditionTuple.from_typed_dict(cast(ParseCondition, e))
                    key = (e.caller, e.caller_port)
                else:
                    raise Exception("Unknown ParseType")
            yield typ, key, e

    def analysis_output_to_dict_entries(
        self,
        inputfile: AnalysisOutput,
        previous_issue_handles: Optional[AnalysisOutput],
        linemapfile: Optional[str],
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
            for f in previous_issue_handles.file_handles():
                handles = f.read().splitlines()
                previous_handles = set(filter(lambda h: not h.startswith("#"), handles))

        log.info("Parsing analysis output...")
        for typ, key, e in self._analysis_output_to_parsed_tuples(inputfile):
            if typ == ParseType.ISSUE:
                e = cast(ParseIssueTuple, e)
                # We are only interested in issues that weren't in the previous
                # analysis.
                if not self._is_existing_issue(linemap, previous_handles, e, key):
                    issues.append(e.interned())
            elif typ == ParseType.PRECONDITION or typ == ParseType.POSTCONDITION:
                e = cast(ParseConditionTuple, e)
                conditions[typ][key].append(e.interned())

        return {
            "issues": issues,
            "preconditions": conditions[ParseType.PRECONDITION],
            "postconditions": conditions[ParseType.POSTCONDITION],
        }

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
        self, input: AnalysisOutput, summary: Summary
    ) -> Tuple[DictEntries, Summary]:
        return (
            self.analysis_output_to_dict_entries(
                input,
                summary.get("previous_issue_handles"),
                summary.get("old_linemap_file"),
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

    # Instead of returning the actual json from the AnalysisOutput, we return
    # location information so it can be retrieved later.
    def get_json_file_offsets(self, input: AnalysisOutput) -> Iterable[EntryPosition]:
        raise NotImplementedError("get_json_file_offset not implemented")

    # Given a path and an offset, return the json in mostly-raw form.
    def get_json_from_file_offset(
        self, path: str, offset: int
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError("get_json_from_file_offset not implemented")
