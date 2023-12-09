# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import annotations

import logging
from collections import namedtuple
from itertools import tee
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple, Type, Union

from munch import Munch
from sqlalchemy import Column, exc, inspect, String, tuple_, types
from sqlalchemy.dialects import mysql, sqlite
from sqlalchemy.dialects.mysql import BIGINT
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import Session

from .db import DB
from .iterutil import inclusive_range, split_every

log: logging.Logger = logging.getLogger("sapp")


# Currently matches the value in `bulk_saver.py`
BATCH_SIZE = 30000

BASE_TABLE_ARGS = (
    {
        "mysql_engine": "InnoDB",
        "mysql_charset": "latin1",
        "mysql_collate": "latin1_bin",
    },
)

# The following three DBID classes require some explanation. Normally models
# will reference each other by their id. But we do bulk insertion at the end
# of our processing, which means the id isn't set until later. Having a DBID
# object allows these models to reference each other before that point. When
# we are ready to insert into the database, PrimaryKeyGenerator will give it
# an ID. Any other models referencing that DBID object will now be able to use
# the real id.


class DBID:
    __slots__ = ["_id", "is_new", "local_id"]

    # Temporary IDs that are local per run (local_id) are assigned for each
    # DBID object on creation. This acts as a key for the object in map-like
    # structures of DB objects without having to define a hashing function for
    # each of them. next_id tracks the next available int to act as an id.
    next_id: int = 0

    def __init__(self, id: Union[int, None, DBID] = None) -> None:
        self.resolve(id)
        self.local_id: int = DBID.next_id
        DBID.next_id += 1

    def resolve(self, id: Union[int, None, DBID], is_new: bool = True) -> DBID:
        self._check_type(id)
        self._id = id
        self.is_new = is_new
        return self

    def resolved(self) -> Optional[int]:
        id = self._id

        # We allow one level of a DBID pointing to another DBID
        if isinstance(id, DBID):
            id = id.resolved()

        return id

    def _check_type(self, id: Union[int, None, DBID]) -> None:
        if not isinstance(id, (int, type(None), DBID)):
            raise TypeError(
                "id expected to be type '{}' but was type '{}'".format(int, type(id))
            )

    # Allow DBIDs to be added and compared as ints
    def __int__(self) -> int:
        resolved = self.resolved()
        if resolved is None:
            raise TypeError(f"cannot convert unset {repr(self)} to int")
        return resolved

    def __str__(self) -> str:
        return str(self.resolved())

    def __add__(self, other: Union[DBID, int]) -> int:
        return int(self) + int(other)

    def __lt__(self, other: Union[DBID, int]) -> bool:
        return int(self) < int(other)

    def __gt__(self, other: Union[DBID, int]) -> bool:
        return int(self) > int(other)

    def __ge__(self, other: Union[DBID, int]) -> bool:
        return int(self) >= int(other)

    def __le__(self, other: Union[DBID, int]) -> bool:
        return int(self) <= int(other)

    def __repr__(self) -> str:
        return "<{}(id={}) object at 0x{:x}>".format(
            self.__class__.__name__, self._id, id(self)
        )


class DBIDType(types.TypeDecorator):
    impl = types.Integer
    cache_ok = False

    # pyre-fixme[3]: Return type must be annotated.
    def process_bind_param(self, value: Optional[Union[int, DBID]], dialect: Dialect):
        # If it is a DBID wrapper, then write the contained value. Otherwise it
        # may be resolved already, or None.
        if isinstance(value, DBID):
            return value.resolved()
        else:
            return value

    def process_result_value(
        self, value: Optional[Union[int, DBID]], dialect: Dialect
    ) -> DBID:
        return DBID(value)

    # pyre-fixme[3]: Return type must be annotated.
    def load_dialect_impl(self, dialect: Dialect):
        if dialect.name == "mysql":
            return dialect.type_descriptor(mysql.INTEGER(unsigned=True))
        return self.impl


class BIGDBIDType(DBIDType):
    impl = types.BigInteger

    # pyre-fixme[3]: Return type must be annotated.
    def load_dialect_impl(self, dialect: Dialect):
        if dialect.name == "mysql":
            return dialect.type_descriptor(mysql.BIGINT(unsigned=True))
        elif dialect.name == "sqlite":
            # SQLite only supports auto-increment for INTEGER not BIGINT.
            # INTEGER in SQLite also natively supports 64-bit values.
            # - https://www.sqlite.org/datatype3.html
            # - https://docs.sqlalchemy.org/en/20/dialects/sqlite.html#sqlite-autoincrement  # noqa: B950
            return dialect.type_descriptor(sqlite.INTEGER())
        return self.impl


class PrepareMixin:
    @classmethod
    def prepare(
        cls,
        database: DB,
        pkgen: PrimaryKeyGeneratorBase,
        items: Iterable[PrepareMixin],
    ) -> Iterator[PrepareMixin]:
        """This is called immediately before the items are written to the
        database. pkgen is passed in to allow last-minute resolving of ids.
        """
        for item in cls.merge(database, items):
            if hasattr(item, "id"):
                # pyre-fixme[16]: `PrepareMixin` has no attribute `id` (we checked)
                item.id.resolve(id=pkgen.get(cls), is_new=True)
            yield item

    @classmethod
    def merge(
        cls, database: DB, items: Iterable[PrepareMixin]
    ) -> Iterable[PrepareMixin]:
        """Models should override this to perform a merge"""
        return items

    @classmethod
    def _merge_by_keys(
        cls, database: DB, items: Iterable[PrepareMixin], *key_attributes: Column
    ) -> Iterator[PrepareMixin]:
        """An object can have multiple attributes as its key. This merges the
        items to be added with existing items in the database based on their
        key(s).

        session: Session object for querying the DB.
        items: Iterator of items to be added to the DB.
        key_attributes: List of attributes of the object/class that represent the
               object's key.

        Returns the next item (in items) that is not already in the DB.
        """
        # Guard against `items` being an iterator: we need to iterate it twice
        items = list(items)

        def key_for_item(item: PrepareMixin) -> Tuple[...]:
            return tuple(getattr(item, attr.key) for attr in key_attributes)

        # Create a set of keys for each item
        #
        # An item's keys is a tuple containing the item's `key_attributes` values
        # in the same order as `key_attributes`
        #
        # For example, if `key_attributes` is `[SharedText.kind, SharedText.contents]`,
        # then a key may be `tuple("feature", "via:tito")`
        keys = {key_for_item(i) for i in items}

        # Find existing items.
        existing_ids = {}  # map of item_hash -> existing ID
        cls_attrs = [getattr(cls, attr.key) for attr in key_attributes]
        for fetch_keys in split_every(BATCH_SIZE, keys):
            with database.make_session() as session:
                existing_items = (
                    # pyre-fixme[16]: `PrepareMixin` has no attribute `id`.
                    session.query(cls.id, *cls_attrs)
                    .filter(tuple_(*cls_attrs).in_(fetch_keys))
                    .all()
                )
            for existing_item in existing_items:
                existing_ids[key_for_item(existing_item)] = existing_item.id

        # Now see if we can merge
        new_items = {}
        for i in items:
            key = key_for_item(i)
            if key in existing_ids:
                # The key is already in the DB
                i.id.resolve(existing_ids[key], is_new=False)
            elif key in new_items:
                # The key is already in the list of new items
                i.id.resolve(new_items[key].id, is_new=False)
            else:
                # The key is new
                new_items[key] = i
                yield i

    @classmethod
    # pyre-fixme[3]: Return type must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    def _merge_assocs(cls, database: DB, items, id1, id2):
        new_items = {}
        for i in items:
            r1 = getattr(i, id1.key)
            r2 = getattr(i, id2.key)
            key = (r1.resolved(), r2.resolved())
            if key not in new_items:
                new_items[key] = i
                yield i


# The record mixin class is more efficient than the MutableRecordMixin, so it
# should be preferred. But the performance isn't from the mutability, it's
# because we use namedtuples, which creates a new class on demand, which uses
# __slots__, which is more efficient. Both of these mixins can be replaced when
# we have dynamically created classes with the slots set. But until then,
# prefer RecordMixin unless you need to change fields after creation.
class RecordMixin:
    # pyre-fixme[4]: Attribute must be annotated.
    _record = None

    @classmethod
    # pyre-fixme[3]: Return type must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    def Record(cls, extra_fields=None, **kwargs):
        if not cls._record:
            if not extra_fields:
                extra_fields = []
            mapper = inspect(cls)
            keys = [c.key for c in mapper.column_attrs] + ["model"] + extra_fields
            cls._record = namedtuple(cls.__name__ + "Record", keys)

        return cls._record(model=cls, **kwargs)

    @classmethod
    # pyre-fixme[3]: Return type must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    def to_dict(cls, obj):
        return obj._asdict()


class MutableRecordMixin:
    @classmethod
    # pyre-fixme[2]: Parameter must be annotated.
    def Record(cls, **kwargs) -> Munch:
        return Munch(model=cls, **kwargs)

    @classmethod
    # pyre-fixme[3]: Return type must be annotated.
    # pyre-fixme[2]: Parameter must be annotated.
    def to_dict(cls, obj):
        return obj.toDict()


class PrimaryKeyBase(PrepareMixin, RecordMixin):  # noqa
    """Subclass this and include your declarative_base mixin"""

    __tablename__ = "primary_keys"
    __table_args__: Tuple[Dict[str, str]] = BASE_TABLE_ARGS

    # pyre-fixme[8]: Attribute has type `str`; used as `Column[str]`.
    table_name: str = Column(
        String(length=100),
        doc="Name of the table that this row stores the next available primary key for",
        nullable=False,
        primary_key=True,
    )

    # pyre-fixme[8]: Attribute has type `int`; used as
    #  `Column[Variable[sqlalchemy.sql.type_api._U]]`.
    current_id: int = Column(
        BIGINT(unsigned=True).with_variant(BIGINT, "sqlite"),
        doc="The current/latest id used in the table.",
        nullable=False,
        primary_key=False,
    )


class PrimaryKeyGeneratorBase:
    """Keep track of DB objects' primary keys by ourselves rather than relying
    on SQLAlchemy, so we can supply them as arguments when creating association
    objects."""

    def __init__(
        self,
        primary_key: Type[PrimaryKeyBase],
        query_classes: Set[Type[object]],
        allowed_id_range: Optional[range] = None,
    ) -> None:
        self.primary_key = primary_key
        self.query_classes = query_classes

        # Map from class name to an ID range (next_id, max_reserved_id)
        self.pks: Dict[str, Tuple[int, int]] = {}

        if allowed_id_range is None:
            # By default, allow all positive signed 64 bit integers
            self.allowed_id_range: range = inclusive_range(1, 2**63 - 1)
        else:
            self.allowed_id_range = allowed_id_range

    def reserve(
        self,
        session: Session,
        # pyre-fixme[24]: Generic type `type` expects 1 type parameter, use
        #  `typing.Type` to avoid runtime subscripting errors.
        saving_classes: List[Type],
        item_counts: Optional[Dict[str, int]] = None,
    ) -> "PrimaryKeyGeneratorBase":
        """
        session - Session for DB operations.
        saving_classes - class objects that need to be saved e.g. Issue, Run
        item_counts - map from class name to the number of items, for preallocating
        id ranges
        """
        query_classes = {cls for cls in saving_classes if cls in self.query_classes}
        for cls in query_classes:
            if item_counts and cls.__name__ in item_counts:
                count = item_counts[cls.__name__]
            else:
                count = 1

            if count > 0:
                self._reserve_id_range(session, cls, count)
            elif count == 0:
                # Don't bother locking rows if there's nothing to reserve
                pass
            else:
                raise ValueError(f"{cls.__name__} count must be >= 0")

        return self

    def _lock_pk_with_retries(
        self, session: Session, cls: Type[PrimaryKeyBase]
    ) -> Optional[PrimaryKeyBase]:
        cls_pk: Optional[object] = None
        retries: int = 6
        while retries > 0:
            try:
                cls_pk = (
                    session.query(self.primary_key)
                    .filter(self.primary_key.table_name == cls.__name__)
                    .with_for_update()
                    .first()
                )
                # if we're here, the record has been locked, or there is no record
                retries = 0
            except exc.OperationalError as ex:
                # Failed to get exclusive lock on the record, so we retry
                retries -= 1
                # Re-raise the exception if our retries are exhausted
                if retries == 0:
                    raise ex
        return cls_pk

    def _reserve_id_range(
        self,
        session: Session,
        # pyre-fixme[24]: Generic type `type` expects 1 type parameter, use
        #  `typing.Type` to avoid runtime subscripting errors.
        cls: Type,
        count: int,
    ) -> None:
        cls_pk = self._lock_pk_with_retries(session, cls)
        if not cls_pk:
            # If cls_pk is None, create a new row in the primary_keys table
            current_id = self._get_initial_current_id(session, cls)
            try:
                session.add(
                    # pyre-fixme[28]: Unexpected keyword argument `table_name`
                    self.primary_key(table_name=cls.__name__, current_id=current_id)
                )
                session.commit()
            except exc.SQLAlchemyError as err:
                # Perhaps another process successfully created the row?
                # Rollback and try to read the new row
                log.error("Writing into the primary keys table failed", exc_info=err)
                session.rollback()
            cls_pk = self._lock_pk_with_retries(session, cls)
            assert cls_pk, (
                "Primary key entry for {cls.__name__} not found "
                "after trying to create it"
            )

        next_id = cls_pk.current_id + 1
        max_id = cls_pk.current_id + count

        assert next_id in self.allowed_id_range, (
            f"Can't reserve any primary keys for {cls.__name__} because the next id="
            f"{next_id} would be outside the allowed {self.allowed_id_range}"
        )
        assert max_id in self.allowed_id_range, (
            f"Can't reserve {count} primary keys for {cls.__name__} because the max id="
            f"{max_id} would be outside the allowed {self.allowed_id_range}"
        )

        cls_pk.current_id = max_id
        session.commit()
        self.pks[cls.__name__] = (next_id, max_id)

    def _get_initial_current_id(
        self,
        session: Session,
        cls: Type[object],
    ) -> int:
        highest_existing_id = self._get_highest_existing_id(session, cls)
        if highest_existing_id is not None:
            assert highest_existing_id in self.allowed_id_range, (
                f"An existing row in the {cls.__name__} table has an "
                f"id={highest_existing_id} which is already outside of the "
                f"allowed {self.allowed_id_range}"
            )
            return highest_existing_id
        else:
            # The calling code will only allocate IDs above the value we return here.
            # We can subtract 1 so new tables start with 1 rather than 2
            return self.allowed_id_range.start - 1

    def _get_highest_existing_id(
        self,
        session: Session,
        cls: Type[object],
    ) -> Optional[int]:
        # pyre-fixme[16]: `object` has no attribute `id`
        row_with_highest_id = session.query(cls.id).order_by(cls.id.desc()).first()
        if row_with_highest_id is None:
            return None
        return row_with_highest_id.id.resolved()

    def get(self, cls: Type[object]) -> int:
        assert cls in self.query_classes, (
            "%s primary key should be generated by SQLAlchemy" % cls.__name__
        )
        assert cls.__name__ in self.pks, (
            "%s primary key needs to be initialized before use" % cls.__name__
        )

        (next_id, max_id) = self.pks[cls.__name__]
        assert next_id <= max_id, (
            "%s reserved primary key range exhausted" % cls.__name__
        )
        assert (
            next_id in self.allowed_id_range
        ), f"{cls.__name__} primary key was outside the allowed {self.allowed_id_range}"

        self.pks[cls.__name__] = (next_id + 1, max_id)
        return next_id
