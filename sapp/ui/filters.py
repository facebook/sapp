# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict
from __future__ import annotations

import json
import logging
from typing import (
    TYPE_CHECKING,
    List,
    Optional,
    Tuple,
)

import graphene
import sqlalchemy
from sqlalchemy import Column, String
from sqlalchemy.orm import Session

from .. import models
from ..db import DB
from ..filter import StoredFilter
from ..models import (
    DBID,
    Base,
    Run,
    RunStatus,
)
from .issues import Instance

if TYPE_CHECKING:
    from pathlib import Path

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


class FilterRecord(Base):
    __tablename__ = "filters"

    name: Column[str] = Column(
        String(length=255), nullable=False, unique=True, primary_key=True
    )
    description: Column[Optional[str]] = Column(String(length=1024), nullable=True)

    json: Column[str] = Column(
        String(length=1024), nullable=False, doc="JSON representation of the filter"
    )

    @staticmethod
    def from_filter(filter: Filter) -> FilterRecord:
        return FilterRecord(
            # pyre-ignore[6]: graphene too dynamic.
            name=filter.name,
            description=filter.description,
            json=filter.json,
        )


def all_filters(session: Session) -> List[Filter]:
    return [Filter.from_record(record) for record in session.query(FilterRecord).all()]


def save_filter(session: Session, filter: Filter) -> None:
    LOG.debug(f"Storing {filter}")
    session.add(FilterRecord.from_filter(filter))
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


class InvalidRunException(Exception):
    pass


def filter_run(
    database: DB,
    run_id_input: int,
    filter_path: Path,
) -> None:
    with database.make_session() as session:
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

        query_results = set()
        for filter_instance in filter_instances:
            query_result = (
                Instance(session, DBID(run_id_input))
                .where_filter(filter_instance)
                .get()
            )
            for issue in query_result:
                query_results.add(issue)

        LOG.info(f"Number of issues after filtering: {len(query_results)}")
        issues_json = [issue.to_json() for issue in query_results]
        print(json.dumps(issues_json, indent=2))
