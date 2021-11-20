# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
import io
import json
import pathlib
from unittest import TestCase, mock

from ...context import Context
from ...db import DB, DBType
from ...filter import FilterRecord
from ...models import (
    create as create_models,
)
from ...pipeline.pysa_taint_parser import Parser as PysaParser
from ...queries import latest_run_id
from ...tests.fake_object_generator import FakeObjectGenerator
from ..filters import (
    all_filters,
    delete_filter,
    delete_filters,
    filter_run,
    save_filter,
    import_filter_from_path,
    EmptyDeletionError,
    FilterNotFound,
    export_filter,
    ServeExportFilter,
    Filter,
)


class RunTest(TestCase):
    def setUp(self) -> None:
        self.db = DB(DBType.MEMORY)
        create_models(self.db)

        self.filter1 = FilterRecord(
            name="Test filter",
            description="Test filter description",
            json=json.dumps({"codes": [5000, 6001]}),
        )
        filter2 = FilterRecord(
            name="Second Test filter",
            description="Second Test filter description",
            json="",
        )
        filter3 = FilterRecord(
            name="Third Test filter",
            description="Third Test filter description",
            json="",
        )

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

        with self.db.make_session() as session:
            session.add(self.filter1)
            session.add(filter2)
            session.add(filter3)
            session.add(run)
            session.commit()

    def testAllFilters(self) -> None:
        with self.db.make_session() as session:
            allFilters = all_filters(session)
            self.assertEqual(len(allFilters), 3)

    def testSaveFilter(self) -> None:
        filter_kwargs = {"codes": [5000, 6001]}
        record = FilterRecord(
            name="New filter",
            description="New Test filter description",
            json=json.dumps(filter_kwargs),
        )
        filter = Filter.from_record(record)

        with self.db.make_session() as session:
            save_filter(session=session, filter=filter)
            filters = session.query(FilterRecord).all()
            self.assertEqual(len(filters), 4)

    def testSaveExistingFilter(self) -> None:
        filter_kwargs = {"codes": [5000, 6001]}
        record = FilterRecord(
            name="Test filter",
            description="New Test filter description ++",
            json=json.dumps(filter_kwargs),
        )
        filter = Filter.from_record(record)
        with self.db.make_session() as session:
            save_filter(session=session, filter=filter)
            filters = session.query(FilterRecord).all()
            self.assertEqual(len(filters), 3)
            updated_filter = (
                session.query(FilterRecord)
                .filter(FilterRecord.name == "Test filter")
                .first()
            )

            self.assertEqual(
                updated_filter.description,  # pyre-ignore[16]
                "New Test filter description ++",
            )

    def testDeleteFilter(self) -> None:
        with self.db.make_session() as session:
            delete_filter(session, name="Test filter")
            filters = all_filters(session)
            self.assertEqual(len(filters), 2)

    def testDeleteFilterNonExistent(self) -> None:
        with self.db.make_session() as session:
            with self.assertRaises(EmptyDeletionError):
                delete_filter(session, "Non Existent Test filter")

    def testDeleteFilters(self) -> None:
        delete_filters(
            database=self.db,
            filter_names=("Test filter", "Second Test filter", "Third Test filter"),
        )
        with self.db.make_session() as session:
            filters = all_filters(session)
            self.assertEqual(len(filters), 0)

    def testImportFilterFromFile(self) -> None:
        with open("test_filter.json", "w", encoding="utf-8") as f:
            data = {
                "name": "A new filter",
                "description": "new filter description",
                "codes": [5000, 6001],
            }
            json.dump(data, f, indent=4)

        path = pathlib.Path("test_filter.json")
        import_filter_from_path(self.db, path)
        pathlib.Path.unlink(path)

        with self.db.make_session() as session:
            filters = all_filters(session)
            self.assertEqual(len(filters), 4)

    def testExportFilter(self) -> None:
        path = pathlib.Path("test_filter1.json")
        export_filter(self.db, "Test filter", path)

        self.assertTrue(path.exists())
        pathlib.Path.unlink(path)

    def testServerExportFilter(self) -> None:
        with self.db.make_session() as session:
            serverExportView = ServeExportFilter(session=session)
            result = serverExportView.dispatch_request(filter_name="Test filter")
            expected_result = {
                "name": "Test filter",
                "description": "Test filter description",
                "codes": [5000, 6001],
            }
            expected_result = json.dumps(expected_result, indent=4)
            self.assertEqual(result, expected_result)

            with self.assertRaises(FilterNotFound):
                serverExportView.dispatch_request(
                    filter_name="Non Existent Test filter"
                )

    @mock.patch("sys.stdout", new_callable=io.StringIO)
    def testFilterRun(self, mock_stdout: io.StringIO) -> None:
        with open("test_filter.json", "w", encoding="utf-8") as f:
            data = {
                "name": "A new filter",
                "description": "new filter description",
                "codes": [6016],
            }
            json.dump(data, f, indent=4)

        with self.db.make_session() as session:
            runId = latest_run_id(session)

            context = Context(database=self.db, parser_class=PysaParser, repository="")
            filter_path = pathlib.Path("test_filter.json")
            filter_run(
                context,
                run_id_input=int(runId),
                filter_path=filter_path,
                output_format="sapp",
            )

            filter_output = json.loads(mock_stdout.getvalue())
            self.assertEqual(len(filter_output["issues"]), 1)
            self.assertEqual(filter_output["issues"][0]["code"], 6016)
