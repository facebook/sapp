# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import dataclasses
import json
import os
from dataclasses import dataclass
from glob import glob
from pathlib import Path
from typing import Any, Dict, IO, Iterable, List, Optional, Set

from .sharded_files import ShardedFile

METADATA_GLOB = "*metadata.json"


@dataclass
class PartialFlowToMark:
    """
    This is a specification of a partial flow that the user wishes us to mark.

    `partial_issue_code` and `full_issue_code` are self-descriptive.

    `full_issue_transform` should be the name of the transform we're looking
    to find in the full issue, and mark matching partial flows.

    `feature` is the schema of the feature to add. `has-{feature}` and
    `{feature}:{issue_instance_id}` will be the resulting features.

    If `is_prefix_flow` is set to True, it means the partial
    issue is a prefix of the full issue. Otherwise, we assume that the partial
    issue is meant to be a suffix of the full issue. If `is_prefix_flow` is true,
    it means that the transform we're searching for in the larger flow is the sink
    of the partial flow. Otherwise, the transform is interpreted as the source.

    `is_prefix_flow` has implications how we search for transforms:

    For a prefix flow, if we find a transform in the postcondition trace of the
    larger issue, we will mark the frame where the transform is applied locally
    as a frame to add a breadcrumb for. If the transform is found in the
    precondition, we'll mark the initial postcondition frames.

    For a suffix flow, we'll flip the logic:
      - If the transform is found in a postcondition trace, the larger
        issue's initial precondition frames.
      - If the transform's in the precondition trace, the source frame for
        the matching precondition callee will be marked.

    The reason for the marking the opposite initial frames from where we started from
    is that the transform frame will *not* appear during the search from the larger
    trace. Marking the other side's root frame allows us to detect the same set of flows
    without doing a complex traversal ourselves.
    """

    partial_issue_code: int
    full_issue_code: int
    full_issue_transform: str
    is_prefix_flow: bool
    feature: str


@dataclass
class Metadata:
    # Used to relativize paths in the results
    repo_roots: Set[str] = dataclasses.field(default_factory=set)
    repository_name: Optional[str] = None
    tool: Optional[str] = None
    analysis_tool_version: Optional[str] = None
    commit_hash: Optional[str] = None
    job_instance: Optional[int] = None
    project: Optional[str] = None
    # Mapping from code to rule metadata.
    # pyre-ignore: we don't have a shape for rules yet.
    rules: Dict[int, Any] = dataclasses.field(default_factory=dict)
    class_type_intervals_filenames: List[str] = dataclasses.field(default_factory=list)
    category_coverage: Dict[str, Any] = dataclasses.field(default_factory=dict)
    partial_flows_to_mark: List[PartialFlowToMark] = dataclasses.field(
        default_factory=list
    )

    def merge(self, o: "Metadata") -> "Metadata":
        return Metadata(
            repo_roots=self.repo_roots | o.repo_roots,
            repository_name=self.repository_name or o.repository_name,
            tool=self.tool or o.tool,
            analysis_tool_version=self.analysis_tool_version or o.analysis_tool_version,
            commit_hash=self.commit_hash or o.commit_hash,
            job_instance=self.job_instance or o.job_instance,
            project=self.project or o.project,
            rules={**self.rules, **o.rules},
            class_type_intervals_filenames=self.class_type_intervals_filenames
            + o.class_type_intervals_filenames,
            category_coverage=self.category_coverage,  # should all be the same
            partial_flows_to_mark=self.partial_flows_to_mark + o.partial_flows_to_mark,
        )


class AnalysisOutputError(Exception):
    pass


class AnalysisOutput:
    """Represents analysis output.

    Possible ways to define, in order of high to low precedence:
    - file_handle: Direct IO object for a single file, useful for testing.
    - filename_specs: List of file names or sharded file patterns.
    - filename_glob and directory: All the files matching the glob in the given directory.
      Avoid patterns like '*', which will include extra, non-analysis files
      in the directory such as the metadata.json.

    Access to the output is provided via generators that provide file handles
    to the diagnostics json (issues), or the summary json (pre and post).
    """

    def __init__(
        self,
        *,
        directory: Optional[str] = None,
        filename_specs: Optional[List[str]] = None,
        filename_glob: Optional[str] = None,
        file_handle: Optional[IO[str]] = None,
        metadata: Optional[Metadata] = None,
        tool: Optional[str] = None,
    ) -> None:
        self.directory = directory
        self.filename_specs: List[str] = filename_specs or []
        self.filename_glob = filename_glob
        self.file_handle = file_handle
        self.metadata = metadata
        self.tool = tool

        if filename_specs is [] and file_handle and hasattr(file_handle, "name"):
            self.filename_specs = [file_handle.name]

    def __str__(self) -> str:
        if self.directory:
            return f"AnalysisOutput({repr(self.directory)})"

        return f"AnalysisOutput({repr(self.filename_specs)})"

    @classmethod
    def from_strs(cls, identifiers: List[str]) -> "AnalysisOutput":
        if len(identifiers) > 1:
            return cls.from_directories(identifiers)
        else:
            return cls.from_str(identifiers[0])

    @classmethod
    def from_str(cls, identifier: str) -> "AnalysisOutput":
        if os.path.isdir(identifier):
            return cls.from_directory(identifier)
        elif os.path.isfile(identifier):
            return cls.from_file(identifier)
        elif os.path.isdir(os.path.dirname(identifier)) and "@" in os.path.basename(
            identifier
        ):
            return cls.from_file(identifier)
        else:
            raise AnalysisOutputError(f"Unrecognized identifier `{identifier}`")

    @classmethod
    def from_directories(cls, directories: List[str]) -> "AnalysisOutput":
        """
        Aggregates several analysis output directories (each of which may themselves be sharded)
        into one AnalysisOutput object. Used for distributed runs of Zoncolan.

        Only supports `filename_spec` in the metadata.json to declare analysis output;
        `filename_glob` and legacy `filenames` are not supported.

        Metadata is naively merged.
        """

        main_metadata = None
        filename_specs = []

        for directory in directories:
            if not os.path.isdir(directory):
                raise AnalysisOutputError(f"`{directory}` is not a directory")
            metadata = {}
            for file in glob(os.path.join(directory, METADATA_GLOB)):
                with open(file) as f:
                    metadata.update(json.load(f))

            filename_specs.extend(
                _get_remapped_filename(metadata, "filename_spec", directory)
            )

            repo_root = metadata.get("repo_root")
            repo_roots = {repo_root if repo_root is not None else metadata["root"]}

            rules = {rule["code"]: rule for rule in metadata.get("rules", [])}
            class_type_intervals_filenames = _get_remapped_filename(
                metadata, "class_type_intervals_filename", directory
            )
            partial_flows_to_mark = _parse_partial_flows_to_mark(
                metadata, "partial_flows"
            )
            this_metadata = Metadata(
                analysis_tool_version=metadata["version"],
                commit_hash=metadata.get("commit"),
                repo_roots=repo_roots,
                job_instance=metadata.get("job_instance"),
                tool=metadata.get("tool"),
                repository_name=metadata.get("repository_name"),
                project=metadata.get("project"),
                rules=rules,
                class_type_intervals_filenames=class_type_intervals_filenames,
                category_coverage=metadata.get("category_coverage", []),
                partial_flows_to_mark=partial_flows_to_mark,
            )
            if not main_metadata:
                main_metadata = this_metadata
            else:
                main_metadata = main_metadata.merge(this_metadata)
        return cls(
            filename_specs=filename_specs,
            metadata=main_metadata,
        )

    @classmethod
    def from_directory(cls, directory: str) -> "AnalysisOutput":
        metadata = {}
        for file in glob(os.path.join(directory, METADATA_GLOB)):
            with open(file) as f:
                metadata.update(json.load(f))

        filename_specs = _get_remapped_filename(metadata, "filename_spec", directory)
        filename_glob = None
        if filename_specs:
            # Ingore all other fallbacks below
            pass
        elif "filename_glob" in metadata:
            filename_glob = metadata["filename_glob"]
            if not filename_glob:
                raise AnalysisOutputError(
                    f"Empty 'filename_glob' not allowed. In {METADATA_GLOB}, "
                    "Use either 'filename_spec' or specify something in "
                    "'filename_glob'."
                )
        else:
            # Legacy
            filename_specs = [
                os.path.join(directory, os.path.basename(metadata["filenames"][0]))
            ]

        repo_root = metadata.get("repo_root")
        repo_roots = {repo_root if repo_root is not None else metadata["root"]}

        rules = {rule["code"]: rule for rule in metadata.get("rules", [])}
        class_type_intervals_filenames = _get_remapped_filename(
            metadata, "class_type_intervals_filename", directory
        )
        partial_flows_to_mark = _parse_partial_flows_to_mark(metadata, "partial_flows")
        return cls(
            directory=directory,
            filename_specs=filename_specs,
            filename_glob=filename_glob,
            metadata=Metadata(
                analysis_tool_version=metadata["version"],
                commit_hash=metadata.get("commit"),
                repo_roots=repo_roots,
                job_instance=metadata.get("job_instance"),
                tool=metadata.get("tool"),
                repository_name=metadata.get("repository_name"),
                project=metadata.get("project"),
                rules=rules,
                class_type_intervals_filenames=class_type_intervals_filenames,
                category_coverage=metadata.get("category_coverage", []),
                partial_flows_to_mark=partial_flows_to_mark,
            ),
        )

    @classmethod
    def from_file(cls, file_name: str) -> "AnalysisOutput":
        # """Pass in either a single file name or a sharded file pattern.
        # Performs early validation by 1) opening the file if it is a single file,
        # or 2) computing and checking the file shards.
        # """
        return cls(filename_specs=[file_name])

    @classmethod
    def from_handle(cls, file_handle: IO[str]) -> "AnalysisOutput":
        return cls(file_handle=file_handle)

    def file_handles(self) -> Iterable[IO[str]]:
        """Generates all file handles represented by the analysis.
        This method manages closing the handles, no cleanup by the caller is needed.
        """
        if self.file_handle:
            yield self.file_handle
            self.file_handle.close()
            self.file_handle = None
        else:
            for name in self.file_names():
                with open(name, "r") as f:
                    yield f

    def file_names(self) -> Iterable[str]:
        """Generates all file names that are used to generate file_handles."""
        filename_specs = self.filename_specs
        filename_glob = self.filename_glob
        for spec in filename_specs:
            if self._is_sharded(spec):
                yield from ShardedFile(spec).get_filenames()
            else:
                yield spec

        if filename_glob is not None:
            directory = self.directory
            assert directory is not None
            # str() cast to convert the returned Path to string for a
            # consistent return type.
            for path in Path(directory).glob(filename_glob):
                yield str(path)

    @classmethod
    def _is_sharded(cls, spec: str) -> bool:
        return "@" in spec

    def has_sharded(self) -> bool:
        return any(self._is_sharded(spec) for spec in self.filename_specs)


def _get_remapped_filename(
    metadata_json: Dict[str, Any], key: str, bundle_directory: str
) -> List[str]:
    """
    When bundles are created on a different host or moved before processing,
    any absolute paths inside the metadata json are no longer valid.

    This function pulls a path from the metadata json and corrects the path
    to be within a bundle directory.
    """
    filename = metadata_json.get(key)
    if filename:
        filename = os.path.join(bundle_directory, os.path.basename(filename))
        return [filename]
    else:
        return []


def _parse_partial_flows_to_mark(
    metadata_json: Dict[str, Any], key: str
) -> List[PartialFlowToMark]:
    parsed = []
    partial_flows_to_mark = metadata_json.get(key, [])
    for partial_flow in partial_flows_to_mark:
        parsed.append(
            PartialFlowToMark(
                full_issue_code=partial_flow["full_issue_code"],
                partial_issue_code=partial_flow["partial_issue_code"],
                full_issue_transform=partial_flow["full_issue_transform"],
                is_prefix_flow=partial_flow["is_prefix_flow"],
                feature=partial_flow["feature"],
            )
        )
    return parsed
