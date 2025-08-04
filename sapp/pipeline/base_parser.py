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
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    Dict,
    Generator,
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
from ..metrics_logger import (
    NoOpMetricsLogger,
    NoOpScopedMetricsLogger,
    ScopedMetricsLogger,
)
from . import (
    Frames,
    IssuesAndFrames,
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


class BaseParser(PipelineStep[AnalysisOutput, IssuesAndFrames]):
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

    @dataclass
    class ParsedFrames:
        preconditions: Frames
        postconditions: Frames

    # @abstractmethod
    def parse(
        self, input: AnalysisOutput
    ) -> Iterable[Union[ParseIssueTuple, ParseConditionTuple]]:
        raise NotImplementedError("Abstract method called!")

    # @abstractmethod
    def parse_handle(
        self, handle: TextIO
    ) -> Iterable[Union[ParseIssueTuple, ParseConditionTuple]]:
        raise NotImplementedError("Abstract method called!")

    def parse_issues_and_collect_frames(
        self, input: AnalysisOutput
    ) -> Generator[ParseIssueTuple, None, ParsedFrames]:
        """Generator that yields issues during parsing
        and finally returns a ParsedFrames containing collected frames
        after parsing is complete.

        Can be overridden instead of `parse` to provide more efficent
        `Frames` implementations
        """
        preconditions = defaultdict(list)
        postconditions = defaultdict(list)
        for e in self.parse(input):
            if isinstance(e, ParseIssueTuple):
                yield e
            elif isinstance(e, ParseConditionTuple):
                key = (e.caller, e.caller_port)
                if e.type == ParseType.PRECONDITION:
                    preconditions[key].append(e)
                elif e.type == ParseType.POSTCONDITION:
                    postconditions[key].append(e)
                else:
                    raise TypeError(f"Unexpected frame type: {type(e.kind)}")
            else:
                raise TypeError(f"Unexpected parsed entry type: {type(e)}")

        return self.ParsedFrames(  # noqa intionally returning a value from a generator
            preconditions=Frames(preconditions),
            postconditions=Frames(postconditions),
        )

    def parse_analysis_output(
        self,
        inputfile: AnalysisOutput,
        previous_issue_handles: Optional[Path] = None,
        linemapfile: Optional[str] = None,
        scoped_metrics_logger: Optional[ScopedMetricsLogger] = None,
    ) -> IssuesAndFrames:
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
        if scoped_metrics_logger is None:
            scoped_metrics_logger = NoOpScopedMetricsLogger(NoOpMetricsLogger())

        issues: List[ParseIssueTuple] = []
        previous_handles: Set[str] = set()

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
        parser_generator = self.parse_issues_and_collect_frames(inputfile)
        parsed_issue_count = 0
        while True:
            try:
                issue = next(parser_generator)
                parsed_issue_count += 1
                # We are only interested in issues that weren't in the previous
                # analysis.
                if not self._is_existing_issue(linemap, previous_handles, issue):
                    issues.append(issue.interned())
            except StopIteration as e:
                parsed_frames = e.value
                break

        preconditions = parsed_frames.preconditions
        postconditions = parsed_frames.postconditions

        log.info(
            f"Parsed {parsed_issue_count} issues ({len(issues)} new), "
            f"{preconditions.frame_count()} preconditions with {preconditions.key_count()} keys, "
            f"and {postconditions.frame_count()} postconditions with {postconditions.key_count()} keys"
        )

        scoped_metrics_logger.add_data("parsed_issues", str(parsed_issue_count))
        scoped_metrics_logger.add_data(
            "parsed_frames",
            str(preconditions.frame_count() + postconditions.frame_count()),
        )
        scoped_metrics_logger.add_data("new_issues", str(len(issues)))

        return IssuesAndFrames(
            issues=issues,
            preconditions=preconditions,
            postconditions=postconditions,
        )

    def _is_existing_issue(
        self,
        linemap: Dict[str, Any],
        old_handles: Set[str],
        new_issue: ParseIssueTuple,
    ) -> bool:
        if new_issue.handle in old_handles:
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
    ) -> Tuple[IssuesAndFrames, Summary]:
        return (
            self.parse_analysis_output(
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
