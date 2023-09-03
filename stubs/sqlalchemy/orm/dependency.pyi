from typing import Any

from .. import exc as sa_exc
from . import util as mapperutil
from .interfaces import (
    MANYTOMANY as MANYTOMANY,
    MANYTOONE as MANYTOONE,
    ONETOMANY as ONETOMANY,
)

class DependencyProcessor(object):
    prop: Any = ...
    cascade: Any = ...
    mapper: Any = ...
    parent: Any = ...
    secondary: Any = ...
    direction: Any = ...
    post_update: Any = ...
    passive_deletes: Any = ...
    passive_updates: Any = ...
    enable_typechecks: Any = ...
    key: Any = ...
    def __init__(self, prop) -> None: ...
    @classmethod
    def from_relationship(cls, prop): ...
    def hasparent(self, state): ...
    def per_property_preprocessors(self, uow): ...
    def per_property_flush_actions(self, uow): ...
    def per_state_flush_actions(self, uow, states, isdelete): ...
    def presort_deletes(self, uowcommit, states): ...
    def presort_saves(self, uowcommit, states): ...
    def process_deletes(self, uowcommit, states): ...
    def process_saves(self, uowcommit, states): ...
    def prop_has_changes(self, uowcommit, states, isdelete): ...

class OneToManyDP(DependencyProcessor):
    def per_property_dependencies(
        self,
        uow,
        parent_saves,
        child_saves,
        parent_deletes,
        child_deletes,
        after_save,
        before_delete,
    ): ...
    def per_state_dependencies(
        self,
        uow,
        save_parent,
        delete_parent,
        child_action,
        after_save,
        before_delete,
        isdelete,
        childisdelete,
    ): ...
    def presort_deletes(self, uowcommit, states): ...
    def presort_saves(self, uowcommit, states): ...
    def process_deletes(self, uowcommit, states): ...
    def process_saves(self, uowcommit, states): ...

class ManyToOneDP(DependencyProcessor):
    def __init__(self, prop) -> None: ...
    def per_property_dependencies(
        self,
        uow,
        parent_saves,
        child_saves,
        parent_deletes,
        child_deletes,
        after_save,
        before_delete,
    ): ...
    def per_state_dependencies(
        self,
        uow,
        save_parent,
        delete_parent,
        child_action,
        after_save,
        before_delete,
        isdelete,
        childisdelete,
    ): ...
    def presort_deletes(self, uowcommit, states): ...
    def presort_saves(self, uowcommit, states): ...
    def process_deletes(self, uowcommit, states): ...
    def process_saves(self, uowcommit, states): ...

class DetectKeySwitch(DependencyProcessor):
    def per_property_preprocessors(self, uow): ...
    def per_property_flush_actions(self, uow): ...
    def per_state_flush_actions(self, uow, states, isdelete): ...
    def presort_deletes(self, uowcommit, states): ...
    def presort_saves(self, uow, states): ...
    def prop_has_changes(self, uow, states, isdelete): ...
    def process_deletes(self, uowcommit, states): ...
    def process_saves(self, uowcommit, states): ...

class ManyToManyDP(DependencyProcessor):
    def per_property_dependencies(
        self,
        uow,
        parent_saves,
        child_saves,
        parent_deletes,
        child_deletes,
        after_save,
        before_delete,
    ): ...
    def per_state_dependencies(
        self,
        uow,
        save_parent,
        delete_parent,
        child_action,
        after_save,
        before_delete,
        isdelete,
        childisdelete,
    ): ...
    def presort_deletes(self, uowcommit, states): ...
    def presort_saves(self, uowcommit, states): ...
    def process_deletes(self, uowcommit, states): ...
    def process_saves(self, uowcommit, states): ...
