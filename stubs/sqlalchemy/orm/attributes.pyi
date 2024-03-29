from collections import namedtuple
from typing import Any, Optional

from . import interfaces
from .base import ATTR_EMPTY as ATTR_EMPTY
from .base import ATTR_WAS_SET as ATTR_WAS_SET
from .base import CALLABLES_OK as CALLABLES_OK
from .base import INIT_OK as INIT_OK
from .base import LOAD_AGAINST_COMMITTED as LOAD_AGAINST_COMMITTED
from .base import NEVER_SET as NEVER_SET
from .base import NO_AUTOFLUSH as NO_AUTOFLUSH
from .base import NO_CHANGE as NO_CHANGE
from .base import NO_VALUE as NO_VALUE
from .base import NON_PERSISTENT_OK as NON_PERSISTENT_OK
from .base import PASSIVE_NO_FETCH as PASSIVE_NO_FETCH
from .base import PASSIVE_NO_FETCH_RELATED as PASSIVE_NO_FETCH_RELATED
from .base import PASSIVE_NO_INITIALIZE as PASSIVE_NO_INITIALIZE
from .base import PASSIVE_NO_RESULT as PASSIVE_NO_RESULT
from .base import PASSIVE_OFF as PASSIVE_OFF
from .base import PASSIVE_ONLY_PERSISTENT as PASSIVE_ONLY_PERSISTENT
from .base import PASSIVE_RETURN_NEVER_SET as PASSIVE_RETURN_NEVER_SET
from .base import RELATED_OBJECT_OK as RELATED_OBJECT_OK
from .base import SQL_OK as SQL_OK
from .base import instance_str as instance_str
from .base import state_str as state_str

class QueryableAttribute(
    interfaces._MappedAttribute, interfaces.InspectionAttr, interfaces.PropComparator
):
    is_attribute: bool = ...
    class_: Any = ...
    key: Any = ...
    impl: Any = ...
    comparator: Any = ...
    def __init__(
        self,
        class_,
        key,
        impl: Optional[Any] = ...,
        comparator: Optional[Any] = ...,
        parententity: Optional[Any] = ...,
        of_type: Optional[Any] = ...,
    ) -> None: ...
    def get_history(self, instance, passive: Any = ...): ...
    def __selectable__(self): ...
    @property
    def info(self): ...
    @property
    def parent(self): ...
    @property
    def expression(self): ...
    def __clause_element__(self): ...
    def adapt_to_entity(self, adapt_to_entity): ...
    def of_type(self, cls): ...
    def label(self, name): ...
    def operate(self, op, *other, **kwargs): ...
    def reverse_operate(self, op, other, **kwargs): ...
    def hasparent(self, state, optimistic: bool = ...): ...
    def __getattr__(self, key): ...
    @property
    def property(self): ...

class InstrumentedAttribute(QueryableAttribute):
    def __set__(self, instance, value): ...
    def __delete__(self, instance): ...
    def __get__(self, instance, owner): ...

def create_proxied_attribute(descriptor): ...

OP_REMOVE: Any = ...
OP_APPEND: Any = ...
OP_REPLACE: Any = ...

class Event(object):
    impl: Any = ...
    op: Any = ...
    parent_token: Any = ...
    def __init__(self, attribute_impl, op) -> None: ...
    def __eq__(self, other): ...
    @property
    def key(self): ...
    def hasparent(self, state): ...

class AttributeImpl(object):
    class_: Any = ...
    key: Any = ...
    callable_: Any = ...
    dispatch: Any = ...
    trackparent: Any = ...
    parent_token: Any = ...
    send_modified_events: Any = ...
    is_equal: Any = ...
    expire_missing: Any = ...
    def __init__(
        self,
        class_,
        key,
        callable_,
        dispatch,
        trackparent: bool = ...,
        extension: Optional[Any] = ...,
        compare_function: Optional[Any] = ...,
        active_history: bool = ...,
        parent_token: Optional[Any] = ...,
        expire_missing: bool = ...,
        send_modified_events: bool = ...,
        **kwargs
    ) -> None: ...
    active_history: Any = ...
    def hasparent(self, state, optimistic: bool = ...): ...
    def sethasparent(self, state, parent_state, value): ...
    def get_history(self, state, dict_, passive: Any = ...): ...
    def get_all_pending(self, state, dict_, passive: Any = ...): ...
    def initialize(self, state, dict_): ...
    def get(self, state, dict_, passive: Any = ...): ...
    def append(self, state, dict_, value, initiator, passive: Any = ...): ...
    def remove(self, state, dict_, value, initiator, passive: Any = ...): ...
    def pop(self, state, dict_, value, initiator, passive: Any = ...): ...
    def set(
        self,
        state,
        dict_,
        value,
        initiator,
        passive: Any = ...,
        check_old: Optional[Any] = ...,
        pop: bool = ...,
    ): ...
    def get_committed_value(self, state, dict_, passive: Any = ...): ...
    def set_committed_value(self, state, dict_, value): ...

class ScalarAttributeImpl(AttributeImpl):
    accepts_scalar_loader: bool = ...
    uses_objects: bool = ...
    supports_population: bool = ...
    collection: bool = ...
    def __init__(self, *arg, **kw) -> None: ...
    def delete(self, state, dict_): ...
    def get_history(self, state, dict_, passive: Any = ...): ...
    def set(
        self,
        state,
        dict_,
        value,
        initiator,
        passive: Any = ...,
        check_old: Optional[Any] = ...,
        pop: bool = ...,
    ): ...
    def fire_replace_event(self, state, dict_, value, previous, initiator): ...
    def fire_remove_event(self, state, dict_, value, initiator): ...
    @property
    def type(self): ...

class ScalarObjectAttributeImpl(ScalarAttributeImpl):
    accepts_scalar_loader: bool = ...
    uses_objects: bool = ...
    supports_population: bool = ...
    collection: bool = ...
    def delete(self, state, dict_): ...
    def get_history(self, state, dict_, passive: Any = ...): ...
    def get_all_pending(self, state, dict_, passive: Any = ...): ...
    def set(
        self,
        state,
        dict_,
        value,
        initiator,
        passive: Any = ...,
        check_old: Optional[Any] = ...,
        pop: bool = ...,
    ): ...
    def fire_remove_event(self, state, dict_, value, initiator): ...
    def fire_replace_event(self, state, dict_, value, previous, initiator): ...

class CollectionAttributeImpl(AttributeImpl):
    accepts_scalar_loader: bool = ...
    uses_objects: bool = ...
    supports_population: bool = ...
    collection: bool = ...
    copy: Any = ...
    collection_factory: Any = ...
    def __init__(
        self,
        class_,
        key,
        callable_,
        dispatch,
        typecallable: Optional[Any] = ...,
        trackparent: bool = ...,
        extension: Optional[Any] = ...,
        copy_function: Optional[Any] = ...,
        compare_function: Optional[Any] = ...,
        **kwargs
    ) -> None: ...
    def get_history(self, state, dict_, passive: Any = ...): ...
    def get_all_pending(self, state, dict_, passive: Any = ...): ...
    def fire_append_event(self, state, dict_, value, initiator): ...
    def fire_pre_remove_event(self, state, dict_, initiator): ...
    def fire_remove_event(self, state, dict_, value, initiator): ...
    def delete(self, state, dict_): ...
    def initialize(self, state, dict_): ...
    def append(self, state, dict_, value, initiator, passive: Any = ...): ...
    def remove(self, state, dict_, value, initiator, passive: Any = ...): ...
    def pop(self, state, dict_, value, initiator, passive: Any = ...): ...
    def set(self, *args, **kwargs): ...
    def set_committed_value(self, state, dict_, value): ...
    def get_collection(
        self, state, dict_, user_data: Optional[Any] = ..., passive: Any = ...
    ): ...

def backref_listeners(attribute, key, uselist): ...

_History = namedtuple("_History", ["added", "unchanged", "deleted"])

class History(_History):
    def __bool__(self): ...
    __nonzero__: Any = ...
    def empty(self): ...
    def sum(self): ...
    def non_deleted(self): ...
    def non_added(self): ...
    def has_changes(self): ...
    def as_state(self): ...
    @classmethod
    def from_scalar_attribute(cls, attribute, state, current): ...
    @classmethod
    def from_object_attribute(cls, attribute, state, current): ...
    @classmethod
    def from_collection(cls, attribute, state, current): ...

HISTORY_BLANK: Any = ...

def get_history(obj, key, passive: Any = ...): ...
def get_state_history(state, key, passive: Any = ...): ...
def has_parent(cls, obj, key, optimistic: bool = ...): ...
def register_attribute(class_, key, **kw): ...
def register_attribute_impl(
    class_,
    key,
    uselist: bool = ...,
    callable_: Optional[Any] = ...,
    useobject: bool = ...,
    impl_class: Optional[Any] = ...,
    backref: Optional[Any] = ...,
    **kw
): ...
def register_descriptor(
    class_,
    key,
    comparator: Optional[Any] = ...,
    parententity: Optional[Any] = ...,
    doc: Optional[Any] = ...,
): ...
def unregister_attribute(class_, key): ...
def init_collection(obj, key): ...
def init_state_collection(state, dict_, key): ...
def set_committed_value(instance, key, value): ...
def set_attribute(instance, key, value): ...
def get_attribute(instance, key): ...
def del_attribute(instance, key): ...
def flag_modified(instance, key): ...
