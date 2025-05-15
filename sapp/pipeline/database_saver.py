# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

#!/usr/bin/env python3

import collections
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import cast, ClassVar, Generic, List, Optional, Tuple, Type, TypeVar

from pyre_extensions import none_throws

from ..bulk_saver import BulkSaver
from ..db import DB
from ..db_support import DBID, dbid_resolution_context
from ..decorators import log_time
from ..metrics_logger import ScopedMetricsLogger
from ..models import (
    ClassTypeInterval,
    Issue,
    MetaRunToRunAssoc,
    PrimaryKeyGenerator,
    Run,
    RunStatus,
    RunSummary,
    TraceFrame,
    TraceFrameAnnotation,
    TraceFrameLeafAssoc,
    TraceKind,
)
from ..trace_graph import TraceGraph
from . import PipelineStep, Summary

log: logging.Logger = logging.getLogger("sapp")

TRun = TypeVar("TRun", bound=Run)


class DatabaseSaver(PipelineStep[List[TraceGraph], RunSummary], Generic[TRun]):
    BULK_SAVER_CLASS: ClassVar[Type[BulkSaver]] = BulkSaver

    def __init__(
        self,
        database: DB,
        run_model: Type[TRun],
        primary_key_generator: Optional[PrimaryKeyGenerator] = None,
        dry_run: bool = False,
        extra_saving_classes: Optional[List[Type[object]]] = None,
        info_path: Optional[str] = None,
    ) -> None:
        self.dbname: str = database.dbname
        self.database = database
        self.run_model = run_model
        self.primary_key_generator: PrimaryKeyGenerator = (
            primary_key_generator or PrimaryKeyGenerator()
        )
        self.extra_saving_classes = extra_saving_classes
        self.dry_run = dry_run
        # pyre-fixme[13]: Attribute `summary` is never initialized.
        self.summary: Summary
        self.info_path = info_path

    @log_time  # pyre-ignore[56]: Pyre can't support this yet.
    def run(
        self,
        input: List[TraceGraph],
        summary: Summary,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> Tuple[List[RunSummary], Summary]:
        self.summary = summary
        run_summaries = []
        for graph, run in zip(input, none_throws(self.summary.runs), strict=True):
            bulk_saver = self.BULK_SAVER_CLASS(
                self.primary_key_generator,
                extra_saving_classes=self.extra_saving_classes,
            )
            self._prep_save(graph, bulk_saver)
            with dbid_resolution_context():
                run_summaries.append(
                    self._save(graph, run, bulk_saver, scoped_metrics_logger)
                )
        return run_summaries, self.summary

    def _prep_save(self, graph: TraceGraph, bulk_saver: BulkSaver) -> None:
        """Prepares the bulk saver to load the trace graph info into the
        database.
        """
        log.info("Preparing bulk save.")
        graph.update_bulk_saver(bulk_saver)
        for trace_kind, unused in none_throws(self.summary.trace_entries).items():
            log.info(
                "Dropped %d unused %s, %d are missing",
                sum(len(v) for v in unused.values()),
                trace_kind,
                len(none_throws(self.summary.missing_traces)[trace_kind]),
            )

    def _save(
        self,
        graph: TraceGraph,
        run: Run,
        bulk_saver: BulkSaver,
        scoped_metrics_logger: ScopedMetricsLogger,
    ) -> RunSummary:
        """Saves bulk saver's info into the databases in bulk."""

        trace_frames = bulk_saver.get_items_to_add(TraceFrame)
        log.info(
            "Saving %d issues, %d trace frames, %d trace annotations, "
            + "%d trace frame leaf assocs, %d class type intervals",
            len(bulk_saver.get_items_to_add(Issue)),
            len(bulk_saver.get_items_to_add(TraceFrame)),
            len(bulk_saver.get_items_to_add(TraceFrameAnnotation)),
            len(bulk_saver.get_items_to_add(TraceFrameLeafAssoc)),
            len(bulk_saver.get_items_to_add(ClassTypeInterval)),
        )

        num_pre = 0
        num_post = 0
        for frame in trace_frames:
            if frame.kind == TraceKind.precondition:
                num_pre += 1
            elif frame.kind == TraceKind.postcondition:
                num_post += 1
        log.info(
            "Within trace frames: %d preconditions, %d postconditions",
            num_pre,
            num_post,
        )

        if not self.dry_run:
            with self.database.make_session() as session:
                pk_gen = self.primary_key_generator.reserve(session, [Run])
                run.id.resolve(id=pk_gen.get(Run), is_new=True)
                session.add(run)
                meta_run_identifier = self.summary.meta_run_identifier
                if meta_run_identifier is not None:
                    session.add(
                        MetaRunToRunAssoc(
                            meta_run_id=cast(DBID, meta_run_identifier),
                            run_id=run.id,
                            run_label=self.summary.meta_run_child_label,
                        )
                    )
                session.commit()

                run_id = run.id.resolved()
                log.info("Created run: %d", run_id)

            # Reserves IDs and removes items that have already been saved
            bulk_saver.prepare_all(self.database)

            # Central issues are saved before local issues. This allows us to
            # only save central issues for new local issues here.
            #
            # Additionally, this allow us to sync information from existing
            # central issues into yet-to-be created local issues here.
            self._save_central_issues_and_sync_local_issues(
                cast(TRun, run), bulk_saver.get_items_to_add(Issue)
            )

            saved_items = bulk_saver.save_all(self.database)
            scoped_metrics_logger.add_data("saved_items", str(saved_items))
            self._save_info(graph)

            # Now that the run is finished, fetch it from the DB again and set its
            # status to FINISHED.
            with self.database.make_session() as session:
                run = session.query(self.run_model).filter_by(id=run_id).one()
                run.status = RunStatus.finished
                run.finished_time = int(datetime.now().timestamp())
                session.add(run)
                session.commit()
                run_summary = run.get_summary()
        else:
            run_summary = self._get_dry_run_summary(graph, run)

        # pyre-fixme[16]: `RunSummary` has no attribute `num_invisible_issues`.
        run_summary.num_invisible_issues = 0
        run_summary.num_missing_preconditions = len(
            none_throws(self.summary.missing_traces)[TraceKind.precondition]
        )
        run_summary.num_missing_postconditions = len(
            none_throws(self.summary.missing_traces)[TraceKind.postcondition]
        )

        return run_summary

    def _save_info(self, graph: TraceGraph) -> None:
        if not self.info_path:
            return
        Path(self.info_path).mkdir(parents=True, exist_ok=True)
        messages: dict[int, str] = {}
        instances = []

        def message_id(graph: TraceGraph, id: DBID) -> int:
            local_id = id.local_id
            if local_id not in messages:
                messages[local_id] = {"id": local_id, "text": graph.get_text(id)}
            return local_id

        for instance in graph.get_issue_instances():
            issue = graph.get_issue(instance.issue_id)
            instances.append(
                {
                    "instance_id": instance.id.resolved(),
                    "code": issue.code,
                    "callable_id": message_id(graph, instance.callable_id),
                    "filename_id": message_id(graph, instance.filename_id),
                    "location": instance.location,
                }
            )
        with open(f"{self.info_path}/messages.ndjson", "w") as f:
            for message in messages.values():
                json.dump(message, f)
                f.write("\n")
        with open(f"{self.info_path}/instances.ndjson", "w") as f:
            for instance in instances:
                json.dump(instance, f)
                f.write("\n")

    def _get_dry_run_summary(self, graph: TraceGraph, run: Run) -> RunSummary:
        return RunSummary(
            commit_hash=run.commit_hash,
            differential_id=run.differential_id,
            id=None,
            job_id=run.job_id,
            num_new_issues=0,
            num_total_issues=graph.get_number_issues(),
            alarm_counts=dict(
                collections.Counter(issue.code for issue in graph.get_issues())
            ),
        )

    def _save_central_issues_and_sync_local_issues(
        self, run: TRun, local_issues: List[Issue]
    ) -> None:
        """Subclasses may implement this to save issue data to a second location
        before the issues saved and the run status is changed to FINISHED. They
        can also modify details of yet-to-be-created local issues to match
        existing central issues."""
        pass
