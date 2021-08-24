# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, List, Tuple, Optional

import graphene
import sqlalchemy
from flask.views import View
from sqlalchemy.orm import Session

from .. import models
from ..context import Context
from ..db import DB
from ..filter import StoredFilter, FilterRecord
from ..models import DBID, Run, RunStatus
from ..sarif import SARIF
from .issues import Instance

if TYPE_CHECKING:
    from pathlib import Path  # usort: skip. Wants trailing whitespace

    from .issues import IssueQueryResult  # noqa

LOG: logging.Logger = logging.getLogger(__name__)


class Filter(graphene.ObjectType):
    name = graphene.String(required=True)
    description = graphene.String()
    json = graphene.String()

    @staticmethod
    def from_record(record: FilterRecord) -> Filter:
        return Filter(
            name=record.name, description=record.description, json=record.json
        )


def all_filters(session: Session) -> List[Filter]:
    return [Filter.from_record(record) for record in session.query(FilterRecord).all()]


def save_filter(session: Session, filter: Filter) -> None:

    existing = (
        session.query(FilterRecord).filter(FilterRecord.name == filter.name).first()
    )

    # pyre-ignore[6]: graphene too dynamic.
    filter_json = json.loads(filter.json)
    filter_json.pop("name", None)
    filter_json.pop("description", None)

    filter_record = StoredFilter(
        # pyre-ignore[6]: graphene too dynamic.
        filter.name,
        # pyre-ignore[6]: graphene too dynamic.
        filter.description or "",
        **filter_json,
    ).to_record()

    if not existing:
        session.add(filter_record)
        LOG.debug(f"Adding {filter}")
    else:
        existing.name = filter_record.name
        existing.description = filter_record.description
        existing.json = filter_record.json
        LOG.debug(f"Updating {filter}")

    session.commit()


class EmptyDeletionError(Exception):
    pass


def delete_filter(session: Session, name: str) -> None:
    deleted_rows = (
        session.query(FilterRecord).filter(FilterRecord.name == name).delete()
    )
    if deleted_rows == 0:
        raise EmptyDeletionError(f'No filter with `name` "{name}" exists.')
    LOG.info(f"Deleting {name}")
    session.commit()


def import_filter_from_path(database: DB, input_filter_path: Path) -> None:
    filter_paths = (
        list(input_filter_path.glob("**/*.json"))
        if input_filter_path.is_dir()
        else [input_filter_path]
    )

    imported_filterrecords = []
    for path in filter_paths:
        filter_instance = StoredFilter.from_file(path)
        imported_filterrecords.append(
            FilterRecord(
                name=filter_instance.name,
                description=filter_instance.description,
                json=filter_instance.to_json(),
            )
        )

    # TODO(T89343050)
    models.create(database)
    with database.make_session() as session:
        with session.begin_nested():
            for record in imported_filterrecords:
                session.merge(record)
                LOG.info(f"`{record.name}` filter has been imported")
        try:
            session.commit()
        except sqlalchemy.exc.DatabaseError:
            LOG.error(
                "Error: Database disk image is malformed. Please recreate your SAPP db"
            )
            raise


def delete_filters(database: DB, filter_names: Tuple[str]) -> None:
    if len(filter_names) <= 0:
        return

    with database.make_session() as session:
        for name in filter_names:
            if name == "":
                LOG.warning("You have provided an empty string for your filter name.")
                continue
            try:
                delete_filter(session, name)
            except EmptyDeletionError as error:
                LOG.exception(error)


class FilterNotFound(Exception):
    pass


def export_filter(
    database: DB, filter_name: str, output_filter_path: Optional[Path] = None
) -> None:
    with database.make_session() as session:
        try:
            record = (
                session.query(FilterRecord)
                .filter(FilterRecord.name == filter_name)
                .one_or_none()
            )
            if not record:
                raise FilterNotFound(
                    f"`{filter_name}` does not exist in `{database.dbname}`"
                )
            storedfilter_instance = StoredFilter.from_record(record)
            if output_filter_path:
                output_filter_path.write_text(storedfilter_instance.to_file())
                LOG.info(f"`{filter_name}` has been exported to `{output_filter_path}`")
            else:
                print(storedfilter_instance.to_file())
        except sqlalchemy.exc.OperationalError:
            LOG.error(
                "Error: Database disk image is malformed or "
                "database has not been initialized properly."
                "Please recreate your SAPP db."
            )
            raise


class ServeExportFilter(View):
    def __init__(self, session: Session) -> None:
        self.session = session

    # pyre-fixme[14]: Inconsistent override
    def dispatch_request(self, filter_name: str) -> str:
        try:
            record = (
                self.session.query(FilterRecord)
                .filter(FilterRecord.name == filter_name)
                .one_or_none()
            )
            if not record:
                raise FilterNotFound(f"`{filter_name}` does not exist")
            storedfilter_instance = StoredFilter.from_record(record)
            return storedfilter_instance.to_file()
        except sqlalchemy.exc.OperationalError:
            LOG.error(
                "Error: Database disk image is malformed or "
                "database has not been initialized properly."
                "Please recreate your SAPP db."
            )
            raise


class InvalidRunException(Exception):
    pass


def filter_run(
    context: Context,
    run_id_input: int,
    filter_path: Path,
    output_format: str,
) -> None:
    with context.database.make_session() as session:
        run_id: Run = (
            session.query(Run)
            .filter(Run.status == RunStatus.FINISHED)
            .filter(Run.id == run_id_input)
            .scalar()
        )
        if run_id is None:
            raise InvalidRunException(
                f"No finished run with ID {run_id_input} exists. Make sure you have run 'sapp analyze' before running `sapp filter`"
            )

        paths = (
            list(filter_path.glob("**/*.json"))
            if filter_path.is_dir()
            else [filter_path]
        )
        filter_instances = [StoredFilter.from_file(path) for path in paths]

        if len(filter_instances) <= 0:
            LOG.error(f"No valid filters found in `{filter_path}`")
            return

        query_results = set()
        for filter_instance in filter_instances:
            query_result = (
                Instance(session, DBID(run_id_input))
                .where_filter(filter_instance)
                .get()
            )
            LOG.info(
                (
                    f"Applying `{filter_instance.name}` to run `{run_id_input}` "
                    f"resulted in {len(query_result)} issues"
                )
            )
            for issue in query_result:
                query_results.add(issue)

        total_filtered_issues_output = (
            f"Total number of issues after filtering: {len(query_results)}"
        )
        if len(query_results) <= 0:
            LOG.error(total_filtered_issues_output)
            return
        else:
            LOG.info(total_filtered_issues_output)
        if output_format == "sapp":
            output_json = {"issues": [issue.to_json() for issue in query_results]}
            print(json.dumps(output_json, indent=2))
        elif output_format == "sarif":
            sarif_output = SARIF(context.tool, session, query_results)
            print(sarif_output.to_json())
