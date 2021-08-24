# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import json
import os
from glob import glob
from pathlib import Path
from typing import IO, Any, Dict, Iterable, List, NamedTuple, Optional, Tuple

from .sharded_files import ShardedFile

METADATA_GLOB = "*metadata.json"


# pyre-fixme[2]: Parameter annotation cannot contain `Any`.
class Metadata(NamedTuple):
    analysis_root: str
    # Used to relativize paths in the results
    repo_roots: List[str] = []
    repository_name: Optional[str] = None
    tool: Optional[str] = None
    analysis_tool_version: Optional[str] = None
    commit_hash: Optional[str] = None
    job_instance: Optional[int] = None
    project: Optional[str] = None
    # Mapping from code to rule metadata.
    # pyre-ignore: we don't have a shape for rules yet.
    rules: Dict[int, Any] = {}
    type_intervals: Dict[Tuple[int, int], str] = {}

    def merge(self, o: "Metadata") -> "Metadata":
        return Metadata(
            analysis_root=self.analysis_root,
            repo_roots=self.repo_roots + o.repo_roots,
            repository_name=self.repository_name or o.repository_name,
            tool=self.tool or o.tool,
            analysis_tool_version=self.analysis_tool_version or o.analysis_tool_version,
            commit_hash=self.commit_hash or o.commit_hash,
            job_instance=self.job_instance or o.job_instance,
            project=self.project or o.project,
            rules={**self.rules, **o.rules},
            type_intervals={**self.type_intervals, **o.type_intervals},
        )


class AnalysisOutputError(Exception):
    pass


class AnalysisOutput(object):
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

            if "filename_spec" in metadata:
                filename_specs.append(
                    os.path.join(directory, os.path.basename(metadata["filename_spec"]))
                )

            repo_root = metadata.get("repo_root")
            analysis_root = metadata["root"]
            rules = {rule["code"]: rule for rule in metadata.get("rules", [])}
            this_metadata = Metadata(
                analysis_tool_version=metadata["version"],
                commit_hash=metadata.get("commit"),
                analysis_root=analysis_root,
                repo_roots=[repo_root],
                job_instance=metadata.get("job_instance"),
                tool=metadata.get("tool"),
                repository_name=metadata.get("repository_name"),
                project=metadata.get("project"),
                rules=rules,
                type_intervals=cls._get_interval_dict(metadata),
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

        filename_specs = []
        filename_glob = None
        if "filename_spec" in metadata:
            filename_specs = [
                os.path.join(directory, os.path.basename(metadata["filename_spec"]))
            ]
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
        analysis_root = metadata["root"]

        rules = {rule["code"]: rule for rule in metadata.get("rules", [])}

        return cls(
            directory=directory,
            filename_specs=filename_specs,
            filename_glob=filename_glob,
            metadata=Metadata(
                analysis_tool_version=metadata["version"],
                commit_hash=metadata.get("commit"),
                analysis_root=analysis_root,
                repo_roots=[repo_root],
                job_instance=metadata.get("job_instance"),
                tool=metadata.get("tool"),
                repository_name=metadata.get("repository_name"),
                project=metadata.get("project"),
                rules=rules,
                type_intervals=cls._get_interval_dict(metadata),
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

    @classmethod
    def _get_interval_dict(cls, metadata: Dict[str, Any]) -> Dict[Tuple[int, int], str]:
        ret_dict = {}
        for entry in metadata.get("intervals", []):
            interval = entry["interval"]
            if not interval:
                continue
            ret_dict[(interval["start"], interval["finish"])] = entry["type"]
        return ret_dict
