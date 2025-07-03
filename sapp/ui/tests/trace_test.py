# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from typing import Any, cast, List
from unittest import TestCase

from ...db import DB, DBType
from ...models import (
    create as create_models,
    DBID,
    SharedText,
    SharedTextKind,
    TraceFrameLeafAssoc,
)
from ...tests.fake_object_generator import FakeObjectGenerator
from .. import trace as trace_module
from ..trace import LeafLookup


class QueryTest(TestCase):
    def setUp(self) -> None:
        self.db = DB(DBType.MEMORY)
        create_models(self.db)
        self.fakes = FakeObjectGenerator()

    # pyre-fixme[3]: Return annotation cannot contain `Any`.
    def _basic_trace_frames(self) -> List[Any]:
        return [
            self.fakes.precondition(
                caller="call1",
                caller_port="root",
                callee="call2",
                callee_port="param0",
                location=(1, 1, 1),
            ),
            self.fakes.precondition(
                caller="call2",
                caller_port="param0",
                callee="leaf",
                callee_port="sink",
                location=(1, 2, 1),
            ),
        ]

    def testLeafLookup(self) -> None:
        shared_texts = [
            SharedText(id=DBID(1), contents="source1", kind=SharedTextKind.source),
            SharedText(id=DBID(2), contents="source2", kind=SharedTextKind.source),
            SharedText(id=DBID(3), contents="source3", kind=SharedTextKind.source),
            SharedText(id=DBID(4), contents="sink4", kind=SharedTextKind.sink),
            SharedText(id=DBID(5), contents="sink5", kind=SharedTextKind.sink),
        ]
        with self.db.make_session() as session:
            for shared_text in shared_texts:
                session.add(shared_text)
            session.commit()

            leaf_lookup = LeafLookup.create(session)

            self.assertEqual(
                leaf_lookup.resolve([1, 2], SharedTextKind.source),
                {"source1", "source2"},
            )
            self.assertEqual(
                leaf_lookup.resolve([3], SharedTextKind.source),
                {"source3"},
            )
            self.assertEqual(
                leaf_lookup.resolve([4, 5], SharedTextKind.sink),
                {"sink4", "sink5"},
            )

    def testNextTraceFrames(self) -> None:
        run = self.fakes.run()
        frames = self._basic_trace_frames()
        sink = self.fakes.sink("sink1")
        self.fakes.saver.add(
            TraceFrameLeafAssoc.Record(
                trace_frame_id=frames[1].id, leaf_id=sink.id, trace_length=1
            )
        )
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

            next_frames = trace_module.next_frames(session, frames[0], {"sink1"}, set())
            self.assertEqual(len(next_frames), 1)
            self.assertEqual(int(next_frames[0][0].id), int(frames[1].id))

    def testNextTraceFramesBackwards(self) -> None:
        run = self.fakes.run()
        frames = [
            self.fakes.precondition(
                caller="call1",
                caller_port="root",
                callee="call3",
                callee_port="param1",
                location=(1, 1, 1),
            ),
            self.fakes.precondition(
                caller="call3",
                caller_port="param1",
                callee="leaf",
                callee_port="sink",
                location=(1, 2, 1),
            ),
        ]
        sink = self.fakes.sink("sink1")
        self.fakes.saver.add_all(
            [
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[0].id, leaf_id=sink.id, trace_length=1
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[1].id, leaf_id=sink.id, trace_length=1
                ),
            ]
        )
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

            next_frames = trace_module.next_frames(
                session,
                cast(trace_module.TraceFrameQueryResult, frames[1]),
                {"sink1"},
                set(),
                backwards=True,
            )

            self.assertEqual(len(next_frames), 1)
            self.assertEqual(int(next_frames[0][0].id), int(frames[0].id))

    def testNextTraceFramesMultipleRuns(self) -> None:
        run1 = self.fakes.run()
        frames = self._basic_trace_frames()
        self.fakes.save_all(self.db)

        run2 = self.fakes.run()
        frames.extend(self._basic_trace_frames())

        sink = self.fakes.sink("sink1")
        self.fakes.saver.add_all(
            [
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[1].id, leaf_id=sink.id, trace_length=0
                ),
                TraceFrameLeafAssoc.Record(
                    trace_frame_id=frames[3].id, leaf_id=sink.id, trace_length=0
                ),
            ]
        )
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run1)
            session.add(run2)
            session.commit()

            next_frames = trace_module.next_frames(session, frames[2], {"sink1"}, set())
            self.assertEqual(len(next_frames), 1)
            self.assertEqual(int(next_frames[0][0].id), int(frames[3].id))
