# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from unittest import TestCase

from ... import queries
from ...db import DB, DBType
from ...models import create as create_models, IssueInstanceSharedTextAssoc
from ...tests.fake_object_generator import FakeObjectGenerator
from ..issues import Instance


class QueryTest(TestCase):
    def setUp(self) -> None:
        self.db = DB(DBType.MEMORY)
        create_models(self.db)
        self.fakes = FakeObjectGenerator()
        run = self.fakes.run()

        issue1 = self.fakes.issue(code=6016, status="do_not_care")
        self.fakes.instance(
            issue_id=issue1.id,
            callable="module.sub.function1",
            filename="module/sub.py",
            min_trace_length_to_sources=1,
            min_trace_length_to_sinks=1,
        )
        self.fakes.save_all(self.db)

        issue2 = self.fakes.issue(code=6017, status="valid_bug")
        self.fakes.instance(
            issue_id=issue2.id,
            callable="module.sub.function2",
            filename="module/sub.py",
            min_trace_length_to_sources=2,
            min_trace_length_to_sinks=2,
        )
        self.fakes.save_all(self.db)

        issue3 = self.fakes.issue(code=6018, status="bad_practice")
        self.fakes.instance(
            issue_id=issue3.id,
            callable="module.function3",
            filename="module/__init__.py",
            min_trace_length_to_sources=3,
            min_trace_length_to_sinks=3,
        )
        self.fakes.save_all(self.db)

        issue4 = self.fakes.issue(code=6019)
        self.fakes.instance(
            issue_id=issue4.id,
            callable="module.function3",
            filename="module/__init__.py",
            min_trace_length_to_sources=0,
            min_trace_length_to_sinks=0,
        )
        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(run)
            session.commit()

    def testWhereCode(self) -> None:
        with self.db.make_session() as session:
            latest_run_id = queries.latest_run_id(session)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_codes_is_any_of([6016]).get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_codes_is_any_of([6017, 6018]).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertIn(2, issue_ids)
            self.assertIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_codes_is_any_of([1234]).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_codes_is_any_of([6017])
                .where_codes_is_any_of([6018])
                .get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

    def testWhereStatus(self) -> None:
        with self.db.make_session() as session:
            latest_run_id = queries.latest_run_id(session)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_status_is_any_of(["do_not_care"]).get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

    def testWhereCallables(self) -> None:
        with self.db.make_session() as session:
            latest_run_id = queries.latest_run_id(session)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_callables_matches(".*sub.*").get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_callables_is_any_of(["1234"]).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_callables_matches(".*function3").get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_callables_is_any_of(["%function3"])
                .where_callables_is_any_of(["%sub%"])
                .get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

    def testWhereFileNames(self) -> None:
        with self.db.make_session() as session:
            latest_run_id = queries.latest_run_id(session)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_path_is_any_of(["1234"]).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_path_is_any_of(["module/s%"]).get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_path_is_any_of(["%__init__.py"]).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertIn(3, issue_ids)

    def testWhereTraceLength(self) -> None:
        with self.db.make_session() as session:
            latest_run_id = queries.latest_run_id(session)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_trace_length_to_sinks(1, 1).get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_trace_length_to_sources(1, 1).get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_trace_length_to_sources(0, 1).get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_trace_length_to_sinks(0, 1).get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_trace_length_to_sinks(0, 2).get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_trace_length_to_sinks(0, 2).get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_trace_length_to_sources(0, 1)
                .where_trace_length_to_sinks(0, 1)
                .get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_trace_length_to_sources(0, 1)
                .where_trace_length_to_sinks(0, 2)
                .get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_trace_length_to_sources(0, 0).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)
            self.assertIn(4, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_trace_length_to_sinks(0, 0).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
            self.assertNotIn(3, issue_ids)
            self.assertIn(4, issue_ids)

    def testWhereSourceName(self) -> None:
        self.fakes.instance()
        source_name_1 = self.fakes.source_detail("source_name_1")
        source_name_2 = self.fakes.source_detail("source_name_2")

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=source_name_1.id, issue_instance_id=1
                )
            )
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=source_name_2.id, issue_instance_id=2
                )
            )
            session.commit()
            latest_run_id = queries.latest_run_id(session)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_source_name_is_any_of(
                    ["source_name_1"]
                ).get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_source_name_matches("source_name_1").get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_source_name_is_any_of(
                    ["source_name_1", "source_name_2"]
                ).get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_source_name_matches("source_name").get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)

    def testWhereSourceKind(self) -> None:
        self.fakes.instance()
        source_kind_1 = self.fakes.source("source_kind_1")
        source_kind_2 = self.fakes.source("source_kind_2")

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=source_kind_1.id, issue_instance_id=1
                )
            )
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=source_kind_2.id, issue_instance_id=2
                )
            )
            session.commit()
            latest_run_id = queries.latest_run_id(session)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_source_kind_is_any_of(
                    ["source_kind_1"]
                ).get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_source_kind_matches("source_kind_1").get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_source_kind_is_any_of(
                    ["source_kind_1", "source_kind_2"]
                ).get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_source_kind_matches("source_kind").get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)

    def testWhereSinkName(self) -> None:
        self.fakes.instance()
        sink_name_1 = self.fakes.sink_detail("sink_name_1")
        sink_name_2 = self.fakes.sink_detail("sink_name_2")

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=sink_name_1.id, issue_instance_id=1
                )
            )
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=sink_name_2.id, issue_instance_id=2
                )
            )
            session.commit()
            latest_run_id = queries.latest_run_id(session)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_sink_name_is_any_of(["sink_name_1"]).get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_sink_name_matches("sink_name_1").get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_sink_name_is_any_of(
                    ["sink_name_1", "sink_name_2"]
                ).get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_sink_name_matches("sink_name").get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)

    def testWhereSinkKind(self) -> None:
        self.fakes.instance()
        sink_kind_1 = self.fakes.sink("sink_kind_1")
        sink_kind_2 = self.fakes.sink("sink_kind_2")

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=sink_kind_1.id, issue_instance_id=1
                )
            )
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=sink_kind_2.id, issue_instance_id=2
                )
            )
            session.commit()
            latest_run_id = queries.latest_run_id(session)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_sink_kind_is_any_of(["sink_kind_1"]).get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_sink_kind_matches("sink_kind_1").get()
            }
            self.assertIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_sink_kind_is_any_of(
                    ["sink_kind_1", "sink_kind_2"]
                ).get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_sink_kind_matches("sink_kind").get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)

    def testWhereAnyFeatures(self) -> None:
        self.fakes.instance()
        feature1 = self.fakes.feature("via:feature1")
        feature2 = self.fakes.feature("via:feature2")
        self.fakes.feature("via:feature3")

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=feature1.id, issue_instance_id=1
                )
            )
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=feature2.id, issue_instance_id=1
                )
            )
            session.commit()
            latest_run_id = queries.latest_run_id(session)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_any_features(["via:feature1"]).get()
            }
            self.assertIn(1, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_any_features(
                    ["via:feature1", "via:feature2"]
                ).get()
            }
            self.assertIn(1, issue_ids)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_any_features(
                    ["via:feature1", "via:feature3"]
                ).get()
            }
            self.assertIn(1, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_any_features(["via:feature3"]).get()
            }
            self.assertNotIn(1, issue_ids)

    def testAssertAllFeatures(self) -> None:
        self.fakes.instance()
        feature1 = self.fakes.feature("via:feature1")
        feature2 = self.fakes.feature("via:feature2")
        self.fakes.feature("via:feature3")

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=feature1.id, issue_instance_id=1
                )
            )
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=feature2.id, issue_instance_id=1
                )
            )
            session.commit()
            latest_run_id = queries.latest_run_id(session)
            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_all_features(["via:feature1"]).get()
            }
            self.assertIn(1, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_all_features(
                    ["via:feature1", "via:feature2"]
                ).get()
            }
            self.assertIn(1, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_all_features(["via:feature3"]).get()
            }
            self.assertNotIn(1, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_all_features(
                    ["via:feature1", "via:feature3"]
                ).get()
            }
            self.assertNotIn(1, issue_ids)

    def testAssertExcludeFeatures(self) -> None:
        feature1 = self.fakes.feature("via:feature1")
        feature2 = self.fakes.feature("via:feature2")
        self.fakes.feature("via:feature3")
        feature4 = self.fakes.feature("via:feature4")

        self.fakes.save_all(self.db)

        with self.db.make_session() as session:
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=feature1.id, issue_instance_id=1
                )
            )
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=feature2.id, issue_instance_id=1
                )
            )
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=feature1.id, issue_instance_id=2
                )
            )
            session.add(
                IssueInstanceSharedTextAssoc(
                    shared_text_id=feature4.id, issue_instance_id=2
                )
            )
            session.commit()
            latest_run_id = queries.latest_run_id(session)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_exclude_features([]).get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_exclude_features(["via:feature1"]).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_exclude_features(["via:feature2"]).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_exclude_features(["via:feature3"]).get()
            }
            self.assertIn(1, issue_ids)
            self.assertIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_exclude_features(
                    ["via:feature1", "via:feature2"]
                ).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_exclude_features(
                    ["via:feature1", "via:feature4"]
                ).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_exclude_features(
                    ["via:feature2", "via:feature4"]
                ).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)

            builder = Instance(session, latest_run_id)
            issue_ids = {
                int(issue.issue_instance_id)
                for issue in builder.where_exclude_features(
                    ["via:feature1", "via:feature3"]
                ).get()
            }
            self.assertNotIn(1, issue_ids)
            self.assertNotIn(2, issue_ids)
