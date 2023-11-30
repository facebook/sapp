# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Bulk saving objects for performance
"""

import logging
from typing import Any, Callable, Dict, Optional

from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .db import DB
from .decorators import log_time
from .iterutil import split_every
from .models import (
    ClassTypeInterval,
    Issue,
    IssueInstance,
    IssueInstanceFixInfo,
    IssueInstanceSharedTextAssoc,
    IssueInstanceTraceFrameAssoc,
    MetaRunIssueInstanceIndex,
    PrimaryKeyGenerator,
    SharedText,
    TraceFrame,
    TraceFrameAnnotation,
    TraceFrameAnnotationTraceFrameAssoc,
    TraceFrameLeafAssoc,
)

log: logging.Logger = logging.getLogger("sapp")


class BulkSaver:
    """Stores new objects created within a run and bulk save them"""

    # order is significant, objects will be saved in this order.
    SAVING_CLASSES_ORDER = [
        SharedText,
        Issue,
        IssueInstanceFixInfo,
        IssueInstance,
        IssueInstanceSharedTextAssoc,
        TraceFrame,
        IssueInstanceTraceFrameAssoc,
        TraceFrameAnnotation,
        TraceFrameLeafAssoc,
        TraceFrameAnnotationTraceFrameAssoc,
        ClassTypeInterval,
        MetaRunIssueInstanceIndex,
    ]

    # These will be saved using `_save_batch_and_handle_key_conflicts`
    # since duplicate keys may be created from two seperate runs
    CLASSES_WITH_POTENTIAL_KEY_CONFLICTS = {
        Issue,
    }

    BATCH_SIZE = 30000

    def __init__(
        self, primary_key_generator: Optional[PrimaryKeyGenerator] = None
    ) -> None:
        self.primary_key_generator: PrimaryKeyGenerator = (
            primary_key_generator or PrimaryKeyGenerator()
        )
        self.saving: Dict[str, Any] = {}
        for cls in self.SAVING_CLASSES_ORDER:
            self.saving[cls.__name__] = []

    # pyre-fixme[2]: Parameter must be annotated.
    def add(self, item) -> None:
        assert item.model in self.SAVING_CLASSES_ORDER, (
            "%s should be added with session.add()" % item.model.__name__
        )
        self.saving[item.model.__name__].append(item)

    # pyre-fixme[2]: Parameter must be annotated.
    def add_all(self, items) -> None:
        if items:
            assert items[0].model in self.SAVING_CLASSES_ORDER, (
                "%s should be added with session.add_all()" % items[0].model.__name__
            )
            self.saving[items[0].model.__name__].extend(items)

    # pyre-fixme[3]: Return type must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    def get_items_to_add(self, cls):
        return self.saving[cls.__name__]

    def save_all(
        self, database: DB, before_save: Optional[Callable[[], None]] = None
    ) -> None:
        saving_classes = [
            cls
            for cls in self.SAVING_CLASSES_ORDER
            if len(self.saving[cls.__name__]) != 0
        ]

        item_counts = {
            cls.__name__: len(self.get_items_to_add(cls)) for cls in saving_classes
        }

        with database.make_session() as session:
            pk_gen = self.primary_key_generator.reserve(
                session, saving_classes, item_counts
            )

        for cls in saving_classes:
            log.info(
                f"Merging and generating ids for {len(self.saving[cls.__name__])} "
                f"{cls.__name__}s..."
            )
            self._prepare(database, cls, pk_gen)

        # Used by unit tests to simulate races
        if before_save:
            before_save()

        for cls in saving_classes:
            log.info(f"Saving {len(self.saving[cls.__name__])} {cls.__name__}s...")
            self._save(database, cls, pk_gen)

    @log_time
    # pyre-fixme[2]: Parameter must be annotated.
    def _prepare(self, database: DB, cls, pk_gen: PrimaryKeyGenerator) -> None:
        # We sort keys because bulk insert uses executemany, but it can only
        # group together sequential items with the same keys. If we are scattered
        # then it does far more executemany calls, and it kills performance.
        items = sorted(
            cls.prepare(database, pk_gen, self.saving[cls.__name__]),
            key=lambda r: list(cls.to_dict(r).keys()),
        )
        self.saving[cls.__name__] = items

    @log_time
    # pyre-fixme[2]: Parameter must be annotated.
    def _save(self, database: DB, cls, pk_gen: PrimaryKeyGenerator) -> None:
        items = self.saving[cls.__name__]
        self.saving[cls.__name__] = []  # allow GC after we are done

        # bulk_insert_mappings should only be used for new objects.
        # To update an existing object, just modify its attribute(s)
        # and call session.commit()
        for batch in split_every(self.BATCH_SIZE, items):
            if cls in self.CLASSES_WITH_POTENTIAL_KEY_CONFLICTS:
                self._save_batch_and_handle_key_conflicts(database, cls, batch)
            else:
                self._save_batch(database, cls, batch)

    # Save a batch of records to the database, handling duplicate key errors
    # by skipping those records during insert and then performing an additional merge
    # so all IDs are pointed to records in the database.
    #
    # Concretely, this is useful for Issues, which have a unique index on
    # `handle` and can have duplicate key errors when two processes race to create
    # Issues with the same handle.
    #
    # Why is this needed when we have already merged records with duplicate keys
    # in `_prepare`?
    # There is a race where another script can insert a duplicate after `_prepare` but
    # before `_save`.
    def _save_batch_and_handle_key_conflicts(
        self,
        database: DB,
        # pyre-fixme[2]: Parameter must be annotated.
        cls,
        # pyre-fixme[2]: Parameter must be annotated.
        batch,
    ) -> None:
        with database.make_session() as session:
            records_to_save = [
                # Unlike `bulk_insert_mappings`, the insert APIs will fail if attributes
                # that are not columns are passed in, so remove "model"
                {k: v for k, v in cls.to_dict(r).items() if k != "model"}
                for r in batch
            ]
            dialect = database.engine.dialect.name
            if dialect == "mysql":
                statement = (
                    mysql_insert(cls).values(records_to_save)
                    # Setting a field to itself is a standard way of doing a no-op in
                    # case of existing rows. This is better than using "INSERT IGNORE"
                    # because that ignores all sorts of other errors too.
                    .on_duplicate_key_update({"id": cls.id})
                )
            elif dialect == "sqlite":
                statement = (
                    sqlite_insert(cls).values(records_to_save).on_conflict_do_nothing()
                )
            else:
                raise ValueError(
                    f"Database dialect was {dialect} but only `mysql` or `sqlite` "
                    f"are supported now"
                )
            session.execute(statement)
            session.commit()

        # After the "INSERT ... ON DUPLICATE KEY UPDATE", all records in the batch
        # have been saved by us or by another concurrently-running process. For records
        # saved by another process, their IDs need to be updated.
        #
        # We don't know which records were saved by us and MySQL can't tell us
        # as part of the INSERT, because it has no RETURNING support.
        #
        # Therefore, we re-run the merge implementation on *all* records in the batch.
        # This will re-read keys for all records and handle updating IDs for records
        # that were saved by another process.
        #
        # Rejected Optimization: we could skip this logic if we knew that all records
        # in the batch were saved by us. `CursorResult.rowcount` /may/ have this
        # information, but it's value apparently depends on MySQL connection flags so
        # we choose to avoid relying on this.
        unsaved_records = list(cls.merge(database, batch))
        if len(unsaved_records) > 0:
            raise ValueError(
                f"There are still {len(unsaved_records)} unsaved {cls.__name__} "
                f"records."
            )

    # Save a batch of records to the database, failing on duplicate key errors.
    #
    # This is more efficient than `_save_batch_and_handle_key_conflicts` for records
    # where we know that races can't occur, because we don't have to read back the
    # inserted records.
    #
    # pyre-fixme[2]: Parameter must be annotated.
    def _save_batch(self, database: DB, cls, batch) -> None:
        with database.make_session() as session:
            session.bulk_insert_mappings(
                cls, (cls.to_dict(r) for r in batch), render_nulls=True
            )
            session.commit()

    def add_trace_frame_leaf_assoc(
        self, message: SharedText, trace_frame: TraceFrame, depth: Optional[int]
    ) -> None:
        self.add(
            TraceFrameLeafAssoc.Record(
                trace_frame_id=trace_frame.id, leaf_id=message.id, trace_length=depth
            )
        )

    def add_issue_instance_trace_frame_assoc(
        self, issue_instance: IssueInstance, trace_frame: TraceFrame
    ) -> None:
        self.add(
            IssueInstanceTraceFrameAssoc.Record(
                issue_instance_id=issue_instance.id, trace_frame_id=trace_frame.id
            )
        )

    def add_issue_instance_shared_text_assoc(
        self, issue_instance: IssueInstance, shared_text: SharedText
    ) -> None:
        self.add(
            IssueInstanceSharedTextAssoc.Record(
                issue_instance_id=issue_instance.id, shared_text_id=shared_text.id
            )
        )

    def add_trace_frame_annotation_trace_frame_assoc(
        self,
        trace_frame_annotation: TraceFrameAnnotation,
        trace_frame: TraceFrame,
    ) -> None:
        self.add(
            TraceFrameAnnotationTraceFrameAssoc.Record(
                trace_frame_annotation_id=trace_frame_annotation.id,
                trace_frame_id=trace_frame.id,
            )
        )

    def dump_stats(self) -> str:
        stat_str = ""
        for cls in self.SAVING_CLASSES_ORDER:
            stat_str += "%s: %d\n" % (cls.__name__, len(self.saving[cls.__name__]))
        return stat_str
