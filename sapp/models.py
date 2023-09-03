# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-unsafe

from __future__ import annotations

import enum
import logging
from datetime import datetime
from decimal import Decimal
from itertools import islice
from typing import Any, Dict, List, NamedTuple, Optional, Set, Type

from graphene_sqlalchemy.converter import (
    convert_column_to_int_or_id,
    convert_column_to_string,
    convert_sqlalchemy_type,
)
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    func,
    Index,
    Integer,
    String,
    types,
)
from sqlalchemy.dialects.mysql import BIGINT
from sqlalchemy.exc import NoSuchTableError, ProgrammingError
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session

from .db import DB
from .db_support import (
    BASE_TABLE_ARGS,
    BIGDBIDType,
    DBID,
    DBIDType,
    MutableRecordMixin,
    PrepareMixin,
    PrimaryKeyBase,
    PrimaryKeyGeneratorBase,
    RecordMixin,
)
from .decorators import classproperty
from .pipeline import SourceLocation

log: logging.Logger = logging.getLogger("sapp")


Base = declarative_base()
INNODB_MAX_INDEX_LENGTH = 767
HANDLE_LENGTH = 255
MESSAGE_LENGTH = 4096
SHARED_TEXT_LENGTH = 4096
META_RUN_ISSUE_INSTANCE_HASH_LENGTH = 16

"""Models used to represent DB entries

An Issue is a particular problem found. It can exist across multiple commits.  A
Run is a single run of Zoncolan over a specific commit. It may find new Issues,
or existing Issues.  Each run is tied to Issues through IssueInstances.
IssueInstances have per run information, like source location, while Issues have
attributes like the status of an issue.
"""


class LeafMapping(NamedTuple):
    caller_leaf: int
    callee_leaf: int
    transform: int


class SourceLocationType(types.TypeDecorator):
    """Defines a new type of SQLAlchemy to store source locations.

    In python land we use SourceLocation, but when stored in the databae we just
    split the fields with |
    """

    impl = types.String
    cache_ok = False

    def __init__(self) -> None:
        super(SourceLocationType, self).__init__(length=255)

    def process_bind_param(self, value, dialect):
        """
        SQLAlchemy uses this to convert a SourceLocation object into a string.
        """
        if value is None:
            return None
        return SourceLocation.to_string(value)

    def process_result_value(self, value, dialect) -> Optional[SourceLocation]:
        """
        SQLAlchemy uses this to convert a string into a SourceLocation object.
        We separate the fields by a |
        """
        if value is None:
            return None

        p = value.split("|")

        if len(p) == 0:
            return None
        return SourceLocation.of(*map(int, p))


class SourceLocationsType(types.TypeDecorator):
    """Defines a type to store multiple source locations in a single string"""

    impl = types.String
    cache_ok = False

    def __init__(self) -> None:
        super(SourceLocationsType, self).__init__(length=4096)

    def process_bind_param(self, value, dialect) -> Optional[str]:
        if value is None:
            return None
        return ",".join([SourceLocation.to_string(location) for location in value])

    def process_result_value(self, value: str, dialect):
        if value is None or value == "":
            return []
        assert isinstance(value, str), "Invalid SourceLocationsType %s" % str(value)
        locations = value.split(",")
        return [SourceLocation.from_string(location) for location in locations]


# See Issue.merge for information about replace_assocs


class IssueDBID(DBID):
    __slots__ = ["replace_assocs"]

    def __init__(self, id=None) -> None:
        super().__init__(id)
        self.replace_assocs = False


class IssueDBIDType(DBIDType):
    def process_result_value(self, value, dialect) -> IssueDBID:
        return IssueDBID(value)


class IssueBIGDBIDType(BIGDBIDType):
    def process_result_value(self, value, dialect) -> IssueDBID:
        return IssueDBID(value)


class IssueInstanceTraceFrameAssoc(Base, PrepareMixin, RecordMixin):
    __tablename__ = "issue_instance_trace_frame_assoc"
    __table_args__ = BASE_TABLE_ARGS

    issue_instance_id = Column(
        "issue_instance_id", BIGDBIDType, primary_key=True, nullable=False
    )

    trace_frame_id = Column(
        "trace_frame_id", BIGDBIDType, primary_key=True, nullable=False, index=True
    )

    issue_instance = relationship(
        "IssueInstance",
        primaryjoin=(
            "IssueInstanceTraceFrameAssoc.issue_instance_id == "
            "foreign(IssueInstance.id)"
        ),
        uselist=False,
        viewonly=True,
    )

    trace_frame = relationship(
        "TraceFrame",
        primaryjoin=(
            "IssueInstanceTraceFrameAssoc.trace_frame_id == foreign(TraceFrame.id)"
        ),
        uselist=False,
        viewonly=True,
    )

    @classmethod
    def merge(cls, session, items):
        return cls._merge_assocs(
            session, items, cls.issue_instance_id, cls.trace_frame_id
        )


class SharedTextKind(enum.Enum):
    # Do NOT reorder the enums. Depending on the type of database, existing
    # DBs may have these enums represented internally as ints based on the
    # order shown here, and changing it here messes up existing data. This
    # also means that new enums should be added AT THE END of the list.
    feature = enum.auto()
    message = enum.auto()
    source = enum.auto()
    sink = enum.auto()
    callable = enum.auto()
    filename = enum.auto()
    source_detail = enum.auto()
    sink_detail = enum.auto()

    @classproperty
    def FEATURE(cls) -> "SharedTextKind":  # noqa
        return cls.feature

    @classproperty
    def MESSAGE(cls) -> "SharedTextKind":  # noqa
        return cls.message

    @classproperty
    def SOURCE(cls) -> "SharedTextKind":  # noqa
        return cls.source

    @classproperty
    def SINK(cls) -> "SharedTextKind":  # noqa
        return cls.sink

    @classproperty
    def CALLABLE(cls) -> "SharedTextKind":  # noqa
        return cls.callable

    @classproperty
    def FILENAME(cls) -> "SharedTextKind":  # noqa
        return cls.filename

    @classproperty
    def SOURCE_DETAIL(cls) -> "SharedTextKind":  # noqa
        return cls.source_detail

    @classproperty
    def SINK_DETAIL(cls) -> "SharedTextKind":  # noqa
        return cls.sink_detail

    @classmethod
    def from_string(cls, string: str) -> Optional[SharedTextKind]:
        return cls.__members__.get(string)


class SharedText(Base, PrepareMixin, RecordMixin):
    """Any string-ish type that can be shared as a property of some other
    object. (e.g. features, sources, sinks). The table name 'messages' is due
    to legacy reasons."""

    __tablename__ = "messages"
    __table_args__ = (
        Index(
            "ix_messages_kind_contents",
            "kind",
            "contents",
            mysql_length={"contents": 767},
        ),
    ) + BASE_TABLE_ARGS

    # pyre-fixme[8]: Attribute has type `DBID`; used as `Column[typing.Any]`.
    id: DBID = Column(BIGDBIDType, primary_key=True)

    # pyre-fixme[8]: Attribute has type `str`; used as `Column[str]`.
    contents: str = Column(
        String(length=SHARED_TEXT_LENGTH),
        nullable=False,
    )

    # pyre-fixme[8]: Attribute has type `SharedTextKind`; used as `Column[str]`.
    kind: SharedTextKind = Column(
        Enum(SharedTextKind), server_default="feature", nullable=False
    )

    issue_instances = association_proxy("shared_text_issue_instance", "issue_instance")

    shared_text_issue_instance = relationship(
        "IssueInstanceSharedTextAssoc",
        primaryjoin=(
            "SharedText.id == foreign(IssueInstanceSharedTextAssoc.shared_text_id)"
        ),
        viewonly=True,
    )

    trace_frames = association_proxy("shared_text_trace_frame", "trace_frames")

    shared_text_trace_frame = relationship(
        "TraceFrameLeafAssoc",
        primaryjoin=("SharedText.id == foreign(TraceFrameLeafAssoc.leaf_id)"),
        viewonly=True,
    )

    # by default, merge shared texts.
    perform_merging: bool = True

    @classmethod
    def performMerging(cls, merge: bool) -> None:
        cls.perform_merging = merge

    @classmethod
    def merge(cls, session, items):
        if cls.perform_merging:
            return cls._merge_by_keys(
                session,
                items,
                lambda item: "%s:%s" % (item.contents, item.kind),
                cls.contents,
                cls.kind,
            )
        else:
            return items


class IssueInstanceSharedTextAssoc(Base, PrepareMixin, RecordMixin):
    """Assoc table between issue instances and its properties that are
    representable by a string. The DB table name and column names are due to
    legacy reasons and warrant some explanation:
    - 'Features' used to be the only shared text of the assoc, now, the assoc
      also accounts for 'Sources' and 'Sinks' and possibly more.
    - 'messages' table used to be only for 'messages', now, it contains
      features, sources and sinks and possibly more.
    - It is expensive to rename the DB tables, so renaming only happened in
      the model. This is why it looks like we have 3 different terms for the
      same thing: 'messages', 'shared_text', 'features'.

    When in doubt, trust the property and method names used in the model and
    refer to the relationship joins for how objects relate to each other.
    """

    __tablename__ = "issue_instance_feature_assoc"
    __table_args__ = BASE_TABLE_ARGS

    issue_instance_id = Column(
        "issue_instance_id", BIGDBIDType, primary_key=True, nullable=False
    )

    shared_text_id = Column("feature_id", BIGDBIDType, primary_key=True, nullable=False)

    issue_instance = relationship(
        "IssueInstance",
        primaryjoin=(
            "IssueInstanceSharedTextAssoc.issue_instance_id =="
            "foreign(IssueInstance.id)"
        ),
        uselist=False,
        viewonly=True,
    )

    shared_text = relationship(
        "SharedText",
        primaryjoin=(
            "IssueInstanceSharedTextAssoc.shared_text_id == foreign(SharedText.id)"
        ),
        uselist=False,
        viewonly=True,
    )

    @classmethod
    def merge(cls, session, items):
        return cls._merge_assocs(
            session, items, cls.issue_instance_id, cls.shared_text_id
        )


class TraceKind(enum.Enum):
    # Do NOT reorder the enums. Depending on the type of database, existing
    # DBs may have these enums represented internally as ints based on the
    # order shown here, and changing it here messes up existing data. This
    # also means that new enums should be added AT THE END of the list.
    precondition = enum.auto()
    postcondition = enum.auto()

    @classproperty
    def PRECONDITION(cls) -> "TraceKind":  # noqa
        return cls.precondition

    @classproperty
    def POSTCONDITION(cls) -> "TraceKind":  # noqa
        return cls.postcondition

    @classmethod
    def create_from_string(cls, value: str) -> TraceKind:
        if value == "precondition":
            return cls.precondition
        if value == "postcondition":
            return cls.postcondition
        raise ValueError(f"`{value}` is not a valid `TraceKind`")


class PurgeStatusForInstance(enum.Enum):
    "Purge status for an instance"

    # Do NOT reorder the enums. Depending on the type of database, existing
    # DBs may have these enums represented internally as ints based on the
    # order shown here, and changing it here messes up existing data. This
    # also means that new enums should be added AT THE END of the list.

    # No purge status set
    none = enum.auto()
    # We want this instance to not be purged
    archive = enum.auto()
    # The instance's dependencies have been marked for archiving
    marked = enum.auto()

    @classproperty
    def NONE(cls) -> str:  # noqa
        # pyre-ignore[7]: Coerce to string for SQLAlchemy
        return cls.none

    @classproperty
    def ARCHIVE(cls) -> str:  # noqa
        # pyre-ignore[7]: Coerce to string for SQLAlchemy
        return cls.archive

    @classproperty
    def MARKED(cls) -> str:  # noqa
        # pyre-ignore[7]: Coerce to string for SQLAlchemy
        return cls.marked


class IssueInstance(Base, PrepareMixin, MutableRecordMixin):
    """A particularly instance of an issue found in a run"""

    __tablename__ = "issue_instances"
    __table_args__ = (
        Index("ix_issue_instances_run_id_purge_status", "run_id", "purge_status"),
    ) + BASE_TABLE_ARGS

    # pyre-fixme[8]: Attribute has type `DBID`; used as `Column[typing.Any]`.
    id: DBID = Column(BIGDBIDType, primary_key=True)

    location = Column(
        SourceLocationType,
        nullable=False,
        doc="Location (possibly a range) of the issue",
    )

    filename_id = Column(BIGDBIDType, nullable=False, server_default="0", default=0)

    filename = relationship(
        "SharedText",
        primaryjoin="foreign(SharedText.id) == IssueInstance.filename_id",
        uselist=False,
        viewonly=True,
    )

    callable_id = Column(BIGDBIDType, nullable=False, server_default="0", default=0)

    callable = relationship(
        "SharedText",
        primaryjoin="foreign(SharedText.id) == IssueInstance.callable_id",
        uselist=False,
        viewonly=True,
    )

    is_new_issue: Column[Optional[bool]] = Column(
        Boolean,
        index=True,
        default=False,
        doc="True if the issue did not exist before this instance",
    )

    run_id = Column(BIGDBIDType, nullable=False, index=False)

    issue_id = Column(BIGDBIDType, nullable=False, index=True)

    issue = relationship(
        "Issue",
        primaryjoin="foreign(Issue.id) == IssueInstance.issue_id",
        uselist=False,
        viewonly=True,
    )

    fix_info_id = Column(BIGDBIDType, nullable=True)

    fix_info = relationship(
        "IssueInstanceFixInfo",
        primaryjoin=("foreign(IssueInstanceFixInfo.id) == IssueInstance.fix_info_id"),
        uselist=False,
        viewonly=True,
    )

    message_id = Column(BIGDBIDType, nullable=True)

    message = relationship(
        "SharedText",
        primaryjoin="foreign(SharedText.id) == IssueInstance.message_id",
        uselist=False,
        viewonly=True,
    )

    trace_frames = association_proxy("issue_instance_trace_frame", "trace_frame")

    issue_instance_trace_frame = relationship(
        "IssueInstanceTraceFrameAssoc",
        primaryjoin=(
            "IssueInstance.id == "
            "foreign(IssueInstanceTraceFrameAssoc.issue_instance_id)"
        ),
        viewonly=True,
    )

    shared_texts = association_proxy("issue_instance_shared_text", "shared_text")

    issue_instance_shared_text = relationship(
        "IssueInstanceSharedTextAssoc",
        primaryjoin=(
            "IssueInstance.id == "
            "foreign(IssueInstanceSharedTextAssoc.issue_instance_id)"
        ),
        viewonly=True,
    )

    min_trace_length_to_sources: Column[Optional[int]] = Column(
        Integer, nullable=True, doc="The minimum trace length to sources"
    )

    min_trace_length_to_sinks: Column[Optional[int]] = Column(
        Integer, nullable=True, doc="The minimum trace length to sinks"
    )

    rank: Column[Optional[int]] = Column(
        Integer,
        server_default="0",
        doc="The higher the rank, the higher the priority for this issue",
    )

    callable_count: Column[Optional[int]] = Column(
        Integer,
        server_default="0",
        doc="Number of issues in this callable for this run",
    )

    min_trace_length_to_entrypoints: Column[Optional[int]] = Column(
        Integer, nullable=True, doc="The minimum trace length to entrypoints"
    )

    purge_status: Column[str] = Column(
        Enum(PurgeStatusForInstance),
        server_default="none",
        nullable=False,
        doc=(
            "Tracks whether Internal deletion jobs have purged "
            "unnecessary trace frames from this instance. "
            "Should NOT be set to anything but the default in SAPP code."
        ),
        index=False,
    )

    def get_shared_texts_by_kind(self, kind: SharedTextKind) -> List[SharedText]:
        return [text for text in self.shared_texts if text.kind == kind]

    def get_trace_frames_by_kind(self, kind: TraceKind):
        return [frame for frame in self.trace_frames if frame.kind == kind]

    @classmethod
    def merge(cls, session, items):
        for i in items:
            # If the issue is new, then the instance has to be new. But note
            # that we still may need RunDiffer, because issues that disappeared
            # for a while and then came back are also marked new.
            i.is_new_issue = i.issue_id.is_new
            # `archive_if_new_issue` is True when we wish to preserve the first
            # instance of all new issues by marking them as `archive`.
            #
            # It is False if we wish instead to save database space and allow
            # the first instance of an issue to be purged.
            if i.archive_if_new_issue and i.is_new_issue:
                i.purge_status = PurgeStatusForInstance.archive
            yield i


class IssueStatus(enum.Enum):
    """Issues are born uncategorized. Humans can
    set it to FALSE_POSITIVE or VALID_BUG upon review."""

    # Do NOT reorder the enums. Depending on the type of database, existing
    # DBs may have these enums represented internally as ints based on the
    # order shown here, and changing it here messes up existing data. This
    # also means that new enums should be added AT THE END of the list.
    """An issue that hasn't been marked as a bug or FP"""
    uncategorized = enum.auto()

    """Not a security bug, but a bad practice. Still needs fixing."""
    bad_practice = enum.auto()

    """False positive from analysis"""
    false_positive = enum.auto()

    """Reviewed and seen to be a valid bug that needs fixing"""
    valid_bug = enum.auto()

    """I don't care about this particular issue,
    but still want to see issues of this kind."""
    do_not_care = enum.auto()

    @classproperty
    def UNCATEGORIZED(cls) -> "IssueStatus":  # noqa
        return cls.uncategorized

    @classproperty
    def BAD_PRACTICE(cls) -> "IssueStatus":  # noqa
        return cls.bad_practice

    @classproperty
    def FALSE_POSITIVE(cls) -> "IssueStatus":  # noqa
        return cls.false_positive

    @classproperty
    def VALID_BUG(cls) -> "IssueStatus":  # noqa
        return cls.valid_bug

    @classproperty
    def DO_NOT_CARE(cls) -> "IssueStatus":  # noqa
        return cls.do_not_care


class Severity(enum.Enum):
    """Severity is Null by default, but set when status is triaged to Valid."""

    # Do NOT reorder the enums. Depending on the type of database, existing
    # DBs may have these enums represented internally as ints based on the
    # order shown here, and changing it here messes up existing data. This
    # also means that new enums should be added AT THE END of the list.

    SEV = enum.auto()
    SEVWorthy = enum.auto()
    Critical = enum.auto()
    Serious = enum.auto()  # Deprecated: replaced by "Significant"
    Limited = enum.auto()
    Significant = enum.auto()


class Issue(Base, PrepareMixin, MutableRecordMixin):
    """An issue coming from the static analysis.

    An issue can persist across multiple runs, even if it moves around in the
    code.
    """

    __tablename__ = "issues"
    __table_args__ = (
        Index("ix_issues_status_severity", "status", "severity"),
    ) + BASE_TABLE_ARGS

    # pyre-fixme[8]: Attribute has type `IssueDBID`; used as `Column[typing.Any]`.
    id: IssueDBID = Column(IssueBIGDBIDType, primary_key=True, nullable=False)

    handle: Column[str] = Column(
        String(length=HANDLE_LENGTH),
        nullable=False,
        unique=True,
        doc="This handle should uniquely identify an issue across runs on "
        + "different code revisions",
    )

    callable_id = Column(
        BIGDBIDType, nullable=False, index=True, server_default="0", default=0
    )

    callable = relationship(
        "SharedText",
        primaryjoin="foreign(SharedText.id) == Issue.callable_id",
        uselist=False,
        viewonly=True,
    )

    code: Column[int] = Column(
        Integer, doc="Code identifiying the issue type", nullable=False, index=True
    )

    instances = relationship(
        "IssueInstance",
        primaryjoin="Issue.id == foreign(IssueInstance.issue_id)",
        viewonly=True,
    )

    status: Column[str] = Column(
        Enum(IssueStatus),
        doc="Shows the issue status from the latest run",
        server_default="uncategorized",
        nullable=False,
    )

    severity: Column[Optional[str]] = Column(
        Enum(Severity),
        doc="Severity of a Valid issue",
        server_default=None,
        nullable=True,
    )

    task_number: Column[Optional[int]] = Column(
        Integer, doc="Task number (not fbid) that is tracking this issue"
    )

    feedback_fbid: Column[Optional[int]] = Column(
        BIGINT(unsigned=True), nullable=True, doc="FBID for EntZoncolanFeedback"
    )

    detected_time: Column[int] = Column(
        BIGINT(20, unsigned=True),
        doc="unix timestamp of first detection",
        nullable=False,
        index=True,
        server_default="0",
    )

    triage_time: Column[Optional[int]] = Column(
        BIGINT(20, unsigned=True),
        doc="unix timestamp of triage (typically first triage from history)",
        nullable=True,
    )

    start_triage_time: Column[Optional[int]] = Column(
        BIGINT(20, unsigned=True),
        doc="unix timestamp of examination leading to triage",
        nullable=True,
    )

    triage_duration: Column[int] = Column(
        BIGINT(20, unsigned=True),
        doc="duration in seconds spent triaging",
        nullable=False,
        server_default="0",
    )

    triaged_by_fbid: Column[Optional[int]] = Column(
        BIGINT(unsigned=True),
        nullable=True,
        doc="FBID for EntInternUser (typically actor of first triage from history)",
    )

    first_instance_id = Column(BIGDBIDType, nullable=True, index=False)

    triaged_instance_id = Column(BIGDBIDType, nullable=True, index=False)

    update_time: Column[int] = Column(
        BIGINT(20, unsigned=True),
        doc="unix timestamp of last update. Not set during initial construction",
        nullable=False,
        index=True,
        server_default="0",
    )

    issue_group_id: Column[Optional[int]] = Column(
        BIGINT(20, unsigned=True),
        doc="issue group id when issue is grouped with others",
        nullable=True,
        server_default=None,
    )

    @classmethod
    def _take(cls, n, iterable):
        "Return first n items of the iterable as a list"
        return list(islice(iterable, n))

    @classmethod
    def merge(cls, session, issues):
        return cls._merge_by_key(session, issues, cls.handle)


class RunStatus(enum.Enum):
    # Do NOT reorder the enums. Depending on the type of database, existing
    # DBs may have these enums represented internally as ints based on the
    # order shown here, and changing it here messes up existing data. This
    # also means that new enums should be added AT THE END of the list.
    finished = enum.auto()
    incomplete = enum.auto()
    skipped = enum.auto()
    failed = enum.auto()

    @classproperty
    def FINISHED(cls) -> "RunStatus":  # noqa
        return cls.finished

    @classproperty
    def INCOMPLETE(cls) -> "RunStatus":  # noqa
        return cls.incomplete

    @classproperty
    def SKIPPED(cls) -> "RunStatus":  # noqa
        return cls.skipped

    @classproperty
    def FAILED(cls) -> "RunStatus":  # noqa
        return cls.failed


class PurgeStatus(enum.Enum):
    "Purge status of a run"

    # Do NOT reorder the enums. Depending on the type of database, existing
    # DBs may have these enums represented internally as ints based on the
    # order shown here, and changing it here messes up existing data. This
    # also means that new enums should be added AT THE END of the list.

    # Run has not been touched by purging automation
    unpurged = enum.auto()
    # Issue instances associated with an untriaged issue have been deleted
    # Trace frames marked as UNREACHABLE have been deleted
    purged = enum.auto()
    # Trace frames not reachable by an issue instance whose issue is triaged have been
    # marked UNREACHABLE.
    ready_to_purge = enum.auto()
    # Runs with archive are never purged
    archive = enum.auto()

    @classproperty
    def UNPURGED(cls) -> str:  # noqa
        # pyre-ignore[7]: Coerce to string for SQLAlchemy
        return cls.unpurged

    @classproperty
    def READY_TO_PURGE(cls) -> str:  # noqa
        # pyre-ignore[7]: Coerce to string for SQLAlchemy
        return cls.ready_to_purge

    @classproperty
    def PURGED(cls) -> str:  # noqa
        # pyre-ignore[7]: Coerce to string for SQLAlchemy
        return cls.purged

    @classproperty
    def ARCHIVE(cls) -> str:  # noqa
        # pyre-ignore[7]: Coerce to string for SQLAlchemy
        return cls.archive


class FrameReachability(enum.Enum):
    "Internal reachability status of a trace frame"

    # Do NOT reorder the enums. Depending on the type of database, existing
    # DBs may have these enums represented internally as ints based on the
    # order shown here, and changing it here messes up existing data. This
    # also means that new enums should be added AT THE END of the list.
    unreachable = enum.auto()
    reachable = enum.auto()

    @classproperty
    def UNREACHABLE(cls) -> str:  # noqa
        # pyre-ignore[7]: Coerce to string for SQLAlchemy
        return cls.unreachable

    @classproperty
    def REACHABLE(cls) -> str:  # noqa
        # pyre-ignore[7]: Coerce to string for SQLAlchemy
        return cls.reachable


CURRENT_DB_VERSION = 1


class Run(Base):
    """A particular run of the static analyzer.

    Each time output is parsed from the static analyzer we generate a new run. A
    run has multiple IssueInstances."""

    __tablename__ = "runs"
    __table_args__ = (
        Index("ix_runs_purge_status_run_status_date", "purge_status", "status", "date"),
    ) + BASE_TABLE_ARGS

    id = Column(BIGDBIDType, primary_key=True)

    job_id: Column[Optional[str]] = Column(String(length=255), index=True)

    date: Column[datetime] = Column(
        DateTime,
        doc="The date/time the analysis was run",
        nullable=False,
        index=True,
    )

    commit_hash: Column[Optional[str]] = Column(
        String(length=255),
        doc="The commit hash of the codebase",
        nullable=True,
        index=True,
    )

    revision_id: Column[Optional[int]] = Column(
        Integer, doc="Phabricator Diff number (DXXXXXX)", nullable=True, index=True
    )

    differential_id: Column[Optional[int]] = Column(
        Integer,
        doc="Phabricator Version number",
        nullable=True,
        index=True,
    )

    hh_version: Column[Optional[str]] = Column(
        String(length=255), doc="The output of hh_server --version"
    )

    branch: Column[Optional[str]] = Column(
        String(length=255),
        doc="Branch the commit is based on",
        nullable=True,
        index=True,
    )

    issue_instances = relationship(
        "IssueInstance",
        primaryjoin="Run.id == foreign(IssueInstance.run_id)",
        backref="run",
        viewonly=True,
    )

    status: Column[str] = Column(
        Enum(RunStatus), server_default="finished", nullable=False, index=True
    )

    status_description: Column[Optional[str]] = Column(
        String(length=255), doc="The reason why a run didn't finish", nullable=True
    )

    kind: Column[Optional[str]] = Column(
        String(length=255),
        doc=(
            "Specify different kinds of runs, e.g. MASTER vs. TEST., GKFORXXX, etc. "
            "in the same DB"
        ),
        nullable=True,
        index=True,
    )

    repository: Column[Optional[str]] = Column(
        String(length=255),
        doc=("The repository that static analysis was run on."),
        nullable=True,
    )

    db_version: Column[int] = Column(
        Integer,
        doc="Tracks under which DB version this was written (for migrations)",
        nullable=False,
        default=CURRENT_DB_VERSION,
        server_default="0",
    )

    purge_status: Column[str] = Column(
        Enum(PurgeStatus),
        server_default="unpurged",
        nullable=False,
        doc=(
            "Tracks whether Internal deletion jobs have purged "
            "unnecessary issue instances and trace frames from this run. "
            "Should NOT be set to anything but the default in SAPP code."
        ),
        index=False,
    )

    def get_summary(self, **kwargs) -> RunSummary:
        session = Session.object_session(self)

        return RunSummary(
            commit_hash=self.commit_hash,
            differential_id=self.differential_id,
            id=self.id.resolved(),
            job_id=self.job_id,
            num_new_issues=self._get_num_new_issue_instances(session),
            num_total_issues=self._get_num_total_issues(session),
            alarm_counts=self._get_alarm_counts(session),
        )

    def _get_num_new_issue_instances(self, session) -> int:
        return (
            session.query(IssueInstance)
            .filter(IssueInstance.run_id == self.id)
            .filter(IssueInstance.is_new_issue.is_(True))
            .count()
        )

    def _get_num_total_issues(self, session) -> int:
        return (
            session.query(IssueInstance).filter(IssueInstance.run_id == self.id).count()
        )

    def _get_alarm_counts(self, session) -> Dict[int, int]:
        return dict(
            session.query(Issue.code, func.count(Issue.code))
            .filter(IssueInstance.run_id == self.id)
            .outerjoin(IssueInstance.issue)
            .group_by(Issue.code)
            .all()
        )


class MetaRun(Base):
    """An identifier that represents multiple runs which should be grouped semantically.

    Meta-runs and runs have a many-to-many relationship, and the purpose of a meta-run
    is to allow querying & displaying results for all related runs without having to
    browse each of them separately."""

    __tablename__ = "metaruns"
    __table_args__ = BASE_TABLE_ARGS

    id = Column(BIGDBIDType, primary_key=True, autoincrement=False)

    # This is the moral equivalent of job_id, but named in a more intuitive manner.
    # Allows determining the latest meta run for each custom run separately.
    custom_run_name: Column[Optional[str]] = Column(String(length=255), nullable=True)

    date: Column[datetime] = Column(
        DateTime, doc="The date/time the meta-run was generated", nullable=False
    )

    # We want to be able to filter meta-runs by completion. Towards that end, we plan on
    # using the information of number of total runs vs. the number of runs written in
    # the database.
    expected_run_count: Column[Optional[int]] = Column(Integer, nullable=True)

    kind: Column[Optional[str]] = Column(
        String(length=255),
        doc=(
            "Specify different kinds of runs, e.g. MASTER vs. TEST., GKFORXXX, etc. "
            "in the same DB"
        ),
        nullable=True,
        index=True,
    )

    db_version: Column[int] = Column(
        Integer,
        doc="Tracks under which DB version this was written (for migrations)",
        nullable=False,
        default=CURRENT_DB_VERSION,
    )

    status: Column[str] = Column(
        Enum(RunStatus), server_default="finished", nullable=False, index=True
    )


class RunSummary:
    def __init__(
        self,
        commit_hash: Optional[str],
        differential_id: Optional[int],
        id: Optional[int],
        job_id: Optional[str],
        num_new_issues: int,
        num_total_issues: int,
        num_missing_preconditions: Optional[int] = None,
        num_missing_postconditions: Optional[int] = None,
        alarm_counts: Optional[Dict[int, int]] = None,
    ) -> None:
        self.commit_hash = commit_hash
        self.differential_id = differential_id
        self.id = id
        self.job_id = job_id
        self.num_new_issues = num_new_issues
        self.num_total_issues = num_total_issues
        self.num_missing_preconditions = num_missing_preconditions
        self.num_missing_postconditions = num_missing_postconditions
        self.alarm_counts: Dict[int, int] = alarm_counts or {}

    def todict(self) -> Dict[str, Any]:
        return self.__dict__

    @classmethod
    def fromdict(cls, d) -> "RunSummary":
        return cls(**d)


class MetaRunToRunAssoc(Base, PrepareMixin, RecordMixin):
    """The responsibility of filling out the meta-run to run assoc is on the child jobs
    of a larger run.
    """

    __tablename__ = "metarun_run_assoc"
    __table_args__ = BASE_TABLE_ARGS

    meta_run_id = Column(BIGDBIDType, nullable=False, primary_key=True)
    run_id = Column(BIGDBIDType, nullable=False, primary_key=True)
    meta_run = relationship(
        "MetaRun",
        primaryjoin=("MetaRunToRunAssoc.meta_run_id == foreign(MetaRun.id)"),
        uselist=False,
        viewonly=True,
    )
    run = relationship(
        "Run",
        primaryjoin=("MetaRunToRunAssoc.run_id == foreign(Run.id)"),
        uselist=False,
        viewonly=True,
    )

    run_label = Column(
        String(length=1024),
        nullable=True,
        doc="Optional label associated with a child run (eg. Buck target)",
    )

    @classmethod
    def merge(cls, session, items):
        return cls._merge_assocs(session, items, cls.meta_run_id, cls.run_id)


class TraceFrameLeafAssoc(Base, PrepareMixin, RecordMixin):
    __tablename__ = "trace_frame_message_assoc"
    __table_args__ = BASE_TABLE_ARGS

    trace_frame_id = Column(BIGDBIDType, nullable=False, primary_key=True)

    leaf_id = Column("message_id", BIGDBIDType, nullable=False, primary_key=True)

    # The minimum trace length unfortunately can be off and actually lead to
    # loops. This is a known problem and any code generating traces should
    # additionally have cycle detection.
    trace_length: Column[Optional[int]] = Column(
        Integer, doc="minimum trace length to the given leaf", nullable=True
    )

    trace_frame = relationship(
        "TraceFrame",
        primaryjoin=("TraceFrameLeafAssoc.trace_frame_id == foreign(TraceFrame.id)"),
        uselist=False,
        viewonly=True,
    )

    leaves = relationship(
        "SharedText",
        primaryjoin="TraceFrameLeafAssoc.leaf_id == foreign(SharedText.id)",
        uselist=False,
        viewonly=True,
    )

    @classmethod
    def merge(cls, session, items):
        return cls._merge_assocs(session, items, cls.trace_frame_id, cls.leaf_id)


class IssueInstanceFixInfo(Base, PrepareMixin, RecordMixin):
    __tablename__ = "issue_instance_fix_info"
    __table_args__ = BASE_TABLE_ARGS

    # pyre-fixme[8]: Attribute has type `DBID`; used as `Column[typing.Any]`.
    id: DBID = Column(BIGDBIDType, nullable=False, primary_key=True)

    fix_info: Column[str] = Column(
        String(length=INNODB_MAX_INDEX_LENGTH), nullable=False
    )

    issue_instance = relationship(
        "IssueInstance",
        primaryjoin=("foreign(IssueInstance.fix_info_id) == IssueInstanceFixInfo.id"),
        uselist=False,
        viewonly=True,
    )


class TraceFrame(Base, PrepareMixin, RecordMixin):
    __tablename__ = "trace_frames"
    __table_args__ = (
        Index("ix_traceframe_run_caller_port", "run_id", "caller_id", "caller_port"),
        Index("ix_traceframe_run_callee_port", "run_id", "callee_id", "callee_port"),
    ) + BASE_TABLE_ARGS

    # pyre-fixme[8]: Attribute has type `DBID`; used as `Column[typing.Any]`.
    id: DBID = Column(BIGDBIDType, nullable=False, primary_key=True)

    kind: Column[str] = Column(Enum(TraceKind), nullable=False, index=False)

    caller_id = Column(BIGDBIDType, nullable=False, server_default="0", default=0)

    caller = relationship(
        "SharedText",
        primaryjoin="foreign(SharedText.id) == TraceFrame.caller_id",
        uselist=False,
        viewonly=True,
    )

    caller_port: Column[str] = Column(
        String(length=INNODB_MAX_INDEX_LENGTH),
        nullable=False,
        server_default="",
        doc="The caller port of this call edge",
    )

    callee_id = Column(BIGDBIDType, nullable=False, server_default="0", default=0)

    callee = relationship(
        "SharedText",
        primaryjoin="foreign(SharedText.id) == TraceFrame.callee_id",
        uselist=False,
        viewonly=True,
    )

    callee_location = Column(
        SourceLocationType,
        nullable=False,
        doc="The location of the callee in the source code (line|start|end)",
    )

    callee_port: Column[str] = Column(
        String(length=INNODB_MAX_INDEX_LENGTH),
        nullable=False,
        server_default="",
        doc="The callee port of this call edge'",
    )

    filename_id = Column(BIGDBIDType, nullable=False, server_default="0", default=0)

    run_id = Column("run_id", BIGDBIDType, nullable=False, index=False)

    type_interval_lower: Column[Optional[int]] = Column(
        Integer, nullable=True, doc="Class interval lower-bound (inclusive)"
    )

    type_interval_upper: Column[Optional[int]] = Column(
        Integer, nullable=True, doc="Class interval upper-bound (inclusive)"
    )

    preserves_type_context: Column[bool] = Column(
        Boolean,
        default=False,
        server_default="0",
        nullable=False,
        doc="Whether the call preserves the calling type context",
    )

    titos = Column(
        SourceLocationsType,
        doc="Locations of TITOs aka abductions for the trace frame",
        nullable=False,
        server_default="",
    )

    reachability: Column[str] = Column(
        Enum(FrameReachability),
        server_default="unreachable",
        nullable=False,
        doc="Reachability of this trace frame, for deletion purposes. "
        + "Is set by internal jobs and should NOT be set to anything but the default in SAPP code.",
    )

    annotations = relationship(
        "TraceFrameAnnotation",
        primaryjoin=("TraceFrame.id == foreign(TraceFrameAnnotation.trace_frame_id)"),
        uselist=True,
        viewonly=True,
    )

    leaves = association_proxy("leaf_assoc", "leaves")
    lengths = association_proxy("leaf_assoc", "trace_length")

    leaf_assoc = relationship(
        "TraceFrameLeafAssoc",
        primaryjoin=("TraceFrame.id == foreign(TraceFrameLeafAssoc.trace_frame_id)"),
        uselist=True,
        viewonly=True,
    )

    issue_instances = association_proxy("trace_frame_issue_instance", "issue_instance")

    trace_frame_issue_instance = relationship(
        "IssueInstanceTraceFrameAssoc",
        primaryjoin=(
            "TraceFrame.id == foreign(IssueInstanceTraceFrameAssoc.trace_frame_id)"
        ),
        viewonly=True,
    )

    leaf_mapping: Set[LeafMapping] = set()

    @staticmethod
    def type_intervals_match_or_ignored(
        caller_start: Optional[int],
        caller_end: Optional[int],
        caller_preserves: Optional[bool],
        callee_start: Optional[int],
        callee_end: Optional[int],
        callee_preserves: Optional[bool],
    ) -> bool:
        """
        returns whether or not to filter based on comparing the type intervals between
        the "caller" trace_frame and the "callee" trace_frame.
        This works both backwards and forwards
        """
        if (
            caller_start is None
            or caller_end is None
            or callee_start is None
            or callee_end is None
            or not callee_preserves
        ):
            # in this case we cannot filter out frames
            return True

        assert caller_start <= caller_end
        assert callee_start <= callee_end

        if caller_start <= callee_start and callee_end <= caller_end:
            # we have a match so we don't filter out the frame
            # in other words for this callee frame the callee is a subset
            # (or the same type) of the callee
            return True

        # we can filter out and we don't have a match return
        # no-match
        # Note that this can happen in a 2 cases
        # (In both cases the caller and callee frams are part of the same base type
        # since we know that the callee 'preserves type')
        # 1. the caller is subset of the callee frame.
        # (e.g. we know the caller is Dog and and the callee could have a trace-frame that
        # allows any animal to traverse.)
        # 2. the caller is an adjacent type
        # (e.g. we know the caller is a Dog and the callee could have a Cat option
        # that needs to be filtered.)
        return False


# Extra bits of information we can show on a TraceFrame.
# This may be a message description, or it may be the start of another series
# of traces leading to some other leaf. TraceFrameAnnotationTraceFrameAssoc
# contains the first hop towards that leaf..
class TraceFrameAnnotation(Base, PrepareMixin, RecordMixin):
    __tablename__ = "trace_frame_annotations"
    __table_args__ = BASE_TABLE_ARGS

    # pyre-fixme[8]: Attribute has type `DBID`; used as `Column[typing.Any]`.
    id: DBID = Column(BIGDBIDType, nullable=False, primary_key=True)

    location = Column(
        SourceLocationType, nullable=False, doc="The location for the message"
    )

    kind: Column[Optional[str]] = Column(String(length=255), nullable=True, index=True)

    # pyre-fixme[8]: Attribute has type `str`; used as `Column[str]`.
    message: str = Column(
        String(length=4096),
        doc="Message describing info about the trace",
        nullable=False,
    )

    leaf_id = Column(BIGDBIDType, nullable=True)
    leaf = relationship(
        "SharedText",
        primaryjoin="foreign(SharedText.id) == TraceFrameAnnotation.leaf_id",
        uselist=False,
        viewonly=True,
    )

    # pyre-fixme[8]: Attribute has type `Optional[str]`; used as `Column[str]`.
    link: Optional[str] = Column(
        String(length=4096),
        doc="An optional URL linking the message to more info (Quandary)",
        nullable=True,
    )

    # pyre-fixme[8]: Attribute has type `Optional[str]`; used as `Column[str]`.
    trace_key: Optional[str] = Column(
        String(length=INNODB_MAX_INDEX_LENGTH),
        nullable=True,
        doc="Link to possible pre/post traces (caller_condition).",
    )

    # pyre-fixme[8]: Attribute has type `DBID`; used as `Column[typing.Any]`.
    trace_frame_id: DBID = Column(BIGDBIDType, nullable=False, index=True)
    trace_frame = relationship(
        "TraceFrame",
        primaryjoin=("TraceFrame.id == foreign(TraceFrameAnnotation.trace_frame_id)"),
        uselist=True,
        viewonly=True,
    )

    child_trace_frames = association_proxy(
        "trace_frame_annotation_trace_frame", "trace_frame"
    )
    trace_frame_annotation_trace_frame = relationship(
        "TraceFrameAnnotationTraceFrameAssoc",
        primaryjoin=(
            "TraceFrameAnnotation.id == "
            "foreign(TraceFrameAnnotationTraceFrameAssoc.trace_frame_annotation_id)"
        ),
        viewonly=True,
    )


# A TraceFrameAnnotation may indicate more traces branching out from a trace
# frame towards a different leaf/trace kind. In that case, this assoc describes
# the first hop trace frame from the annotation. It is similar to
# IssueInstanceTraceFrameAssoc, which indicates the first hop trace frame from
# the issue instance.
class TraceFrameAnnotationTraceFrameAssoc(Base, PrepareMixin, RecordMixin):
    __tablename__ = "trace_frame_annotation_trace_frame_assoc"
    __table_args__ = BASE_TABLE_ARGS

    trace_frame_annotation_id = Column(
        "trace_frame_annotation_id", BIGDBIDType, primary_key=True, nullable=False
    )

    trace_frame_id = Column(
        "trace_frame_id", BIGDBIDType, primary_key=True, nullable=False, index=True
    )

    trace_frame_annotation = relationship(
        "TraceFrameAnnotation",
        primaryjoin=(
            "TraceFrameAnnotationTraceFrameAssoc.trace_frame_annotation_id == "
            "foreign(TraceFrameAnnotation.id)"
        ),
        uselist=False,
        viewonly=True,
    )

    trace_frame = relationship(
        "TraceFrame",
        primaryjoin=(
            "TraceFrameAnnotationTraceFrameAssoc.trace_frame_id == "
            "foreign(TraceFrame.id)"
        ),
        uselist=False,
        viewonly=True,
    )

    @classmethod
    def merge(cls, session, items):
        return cls._merge_assocs(
            session, items, cls.trace_frame_annotation_id, cls.trace_frame_id
        )


class WarningMessage(Base):
    __tablename__ = "warning_messages"
    __table_args__ = BASE_TABLE_ARGS

    code: Column[int] = Column(Integer, autoincrement=False, primary_key=True)

    message: Column[str] = Column(String(length=4096), nullable=False)


class WarningCodeCategory(enum.Enum):
    # Do NOT reorder the enums. Depending on the type of database, existing
    # DBs may have these enums represented internally as ints based on the
    # order shown here, and changing it here messes up existing data. This
    # also means that new enums should be added AT THE END of the list.
    bug = enum.auto()
    code_smell = enum.auto()

    @classproperty
    def BUG(cls) -> "WarningCodeCategory":  # noqa
        return cls.bug

    @classproperty
    def CODE_SMELL(cls) -> "WarningCodeCategory":  # noqa
        return cls.code_smell


class WarningCodeProperties(Base):
    """Contains properties describing each warning code"""

    __tablename__ = "warning_code_properties"
    __table_args__ = BASE_TABLE_ARGS

    code: Column[int] = Column(
        Integer,
        autoincrement=False,
        nullable=False,
        primary_key=True,
        doc="Code identifiying the issue type",
    )

    category: Column[Optional[str]] = Column(
        Enum(WarningCodeCategory),
        nullable=True,
        index=False,
        # pyre-fixme[6]: Expected `str` for 4th param but got `Tuple[str]`.
        doc=(
            "The category of problems that issues in with this warning code "
            "can result in ",
        ),
    )

    new_issue_rate: Column[Optional[Decimal]] = Column(
        Float,
        nullable=True,
        index=False,
        doc="Average number of new issues per day (computed column)",
    )

    bug_count: Column[Optional[int]] = Column(
        Integer,
        nullable=True,
        index=False,
        doc="Number of issues in this category (computed column)",
    )

    avg_trace_len: Column[Optional[Decimal]] = Column(
        Float, nullable=True, index=False, doc="Deprecated. See avg_fwd/bwd_trace_len"
    )

    avg_fwd_trace_len: Column[Optional[Decimal]] = Column(
        Float,
        nullable=True,
        index=False,
        # pyre-fixme[6]: Expected `str` for 4th param but got `Tuple[str]`.
        doc=(
            "Average (min) length of forward traces for the given warning code "
            "(computed column)",
        ),
    )

    avg_bwd_trace_len: Column[Optional[Decimal]] = Column(
        Float,
        nullable=True,
        index=False,
        # pyre-fixme[6]: Expected `str` for 4th param but got `Tuple[str]`.
        doc=(
            "Average (min) length of backward traces for the given warning "
            "code (computed column)",
        ),
    )

    snr: Column[Optional[Decimal]] = Column(
        Float,
        nullable=True,
        index=False,
        doc=(
            "Signal to noise ratio based on triaged issues (computed column). "
            "Ratio of (valid + bad practice) to (false positive + don't care)"
        ),
    )

    is_snr_significant: Column[Optional[bool]] = Column(
        Boolean,
        nullable=True,
        index=False,
        doc=(
            "True if we are confident about the snr (computed column). "
            "Depends on percentage of triaged issues and number of issues."
        ),
    )

    discoverable: Column[Optional[bool]] = Column(
        Boolean,
        nullable=True,
        index=False,
        doc="True if an attacker can discover the issue",
    )

    health_score: Column[Optional[Decimal]] = Column(
        Float,
        nullable=True,
        index=False,
        doc=(
            "Scoring for the health of the warning code, between 0 and 1, "
            "based on the values in the other columns (computed column)"
        ),
    )

    notes: Column[Optional[str]] = Column(
        String(length=4096),
        nullable=True,
        index=False,
        doc="Free form field for note-taking",
    )


class RunOrigin(Base, PrepareMixin, RecordMixin):
    """This table associates runs with metadata concerning how the run was built, which we
    call run origins. An example of run origins is Buck targets."""

    __tablename__ = "run_origins"
    __table_args__ = BASE_TABLE_ARGS

    id = Column(BIGDBIDType, nullable=False, primary_key=True)
    run_id = Column(BIGDBIDType, nullable=False, index=True)
    origin = Column(String(length=255), nullable=False)

    run = relationship(
        "Run",
        primaryjoin=("RunOrigin.run_id == foreign(Run.id)"),
        uselist=False,
        viewonly=True,
    )

    @classmethod
    def merge(cls, session, items):
        return cls._merge_by_key(session, items, cls.run_id)


class ClassTypeInterval(Base, PrepareMixin, RecordMixin):
    """This table can store the class names for type intervals within a run"""

    __tablename__ = "class_type_intervals"
    __table_args__ = (
        Index(
            "ix_class_type_intervals_run_id_class_name",
            "run_id",
            "class_name",
            unique=True,
        ),
        Index("ix_class_type_intervals_bounds", "run_id", "lower_bound", "upper_bound"),
    ) + BASE_TABLE_ARGS

    # Synthetic primary key allows easier pagination when compared to
    # using (run_id, class_name) as a composite primary key
    id = Column("id", BIGDBIDType, nullable=False, primary_key=True)

    run_id = Column(BIGDBIDType, nullable=False)
    class_name = Column(String(length=INNODB_MAX_INDEX_LENGTH), nullable=False)
    lower_bound = Column(Integer, nullable=False)
    upper_bound = Column(Integer, nullable=False)


class MetaRunIssueInstanceIndex(Base, PrepareMixin, RecordMixin):
    """This table is used by the (optional) pipeline step `MetaRunIssueDuplicateFilter`
    to deduplicate issue instances within a meta run."""

    __tablename__ = "metarun_issue_instance_index"
    __table_args__ = (
        Index("ix_metarun_issue_instance_index", "meta_run_id", "issue_instance_hash"),
    ) + BASE_TABLE_ARGS

    issue_instance_id = Column(BIGDBIDType, nullable=False, primary_key=True)
    meta_run_id = Column(BIGDBIDType, nullable=False)
    issue_instance_hash: Column[str] = Column(
        String(length=META_RUN_ISSUE_INSTANCE_HASH_LENGTH),
        nullable=False,
        doc=(
            "This hash should uniquely identify an issue instance "
            "across a given metarun"
        ),
    )


class PrimaryKey(Base, PrimaryKeyBase):
    pass


class PrimaryKeyGenerator(PrimaryKeyGeneratorBase):
    PRIMARY_KEY: Type = PrimaryKey

    QUERY_CLASSES: Set[Type] = {
        Issue,
        IssueInstance,
        IssueInstanceFixInfo,
        SharedText,
        Run,
        TraceFrame,
        TraceFrameAnnotation,
        ClassTypeInterval,
    }


def create(db: DB) -> None:
    try:
        Base.metadata.create_all(db.engine)
    except NoSuchTableError:
        pass
    except ProgrammingError as e:
        if "'JSON NOT NULL" in str(e):
            raise Exception(
                "Could not create JSON columns. "
                + "Check that you are using MySQL 8.0 or later."
            ) from e
        raise


convert_sqlalchemy_type.register(SourceLocationType)(convert_column_to_string)
convert_sqlalchemy_type.register(BIGDBIDType)(convert_column_to_int_or_id)
