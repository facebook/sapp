from typing import Any, Optional
from .. import util
from .interfaces import LoaderStrategy as LoaderStrategy

class UninstrumentedColumnLoader(LoaderStrategy):
    columns: Any = ...
    def __init__(self, parent, strategy_key) -> None: ...
    def setup_query(
        self,
        context,
        entity,
        path,
        loadopt,
        adapter,
        column_collection: Optional[Any] = ...,
        **kwargs
    ): ...
    def create_row_processor(
        self, context, path, loadopt, mapper, result, adapter, populators
    ): ...

class ColumnLoader(LoaderStrategy):
    columns: Any = ...
    is_composite: Any = ...
    def __init__(self, parent, strategy_key) -> None: ...
    def setup_query(
        self,
        context,
        entity,
        path,
        loadopt,
        adapter,
        column_collection,
        memoized_populators,
        **kwargs
    ): ...
    is_class_level: bool = ...
    def init_class_attribute(self, mapper): ...
    def create_row_processor(
        self, context, path, loadopt, mapper, result, adapter, populators
    ): ...

class DeferredColumnLoader(LoaderStrategy):
    columns: Any = ...
    group: Any = ...
    def __init__(self, parent, strategy_key) -> None: ...
    def create_row_processor(
        self, context, path, loadopt, mapper, result, adapter, populators
    ): ...
    is_class_level: bool = ...
    def init_class_attribute(self, mapper): ...
    def setup_query(self, *args, **kw): ...

class LoadDeferredColumns(object):
    key: Any = ...
    def __init__(self, key) -> None: ...
    def __call__(self, state, passive: Any = ...): ...

class AbstractRelationshipLoader(LoaderStrategy):
    mapper: Any = ...
    target: Any = ...
    uselist: Any = ...
    def __init__(self, parent, strategy_key) -> None: ...

class NoLoader(AbstractRelationshipLoader):
    is_class_level: bool = ...
    def init_class_attribute(self, mapper): ...
    def create_row_processor(
        self, context, path, loadopt, mapper, result, adapter, populators
    ): ...

class LazyLoader(AbstractRelationshipLoader, util.MemoizedSlots):
    use_get: Any = ...
    def __init__(self, parent, strategy_key) -> None: ...
    is_class_level: bool = ...
    def init_class_attribute(self, mapper): ...
    def create_row_processor(
        self, context, path, loadopt, mapper, result, adapter, populators
    ): ...

class LoadLazyAttribute(object):
    key: Any = ...
    strategy_key: Any = ...
    def __init__(self, key, initiating_strategy) -> None: ...
    def __call__(self, state, passive: Any = ...): ...

class ImmediateLoader(AbstractRelationshipLoader):
    def init_class_attribute(self, mapper): ...
    def setup_query(
        self,
        context,
        entity,
        path,
        loadopt,
        adapter,
        column_collection: Optional[Any] = ...,
        parentmapper: Optional[Any] = ...,
        **kwargs
    ): ...
    def create_row_processor(
        self, context, path, loadopt, mapper, result, adapter, populators
    ): ...

class SubqueryLoader(AbstractRelationshipLoader):
    join_depth: Any = ...
    def __init__(self, parent, strategy_key) -> None: ...
    def init_class_attribute(self, mapper): ...
    def setup_query(
        self,
        context,
        entity,
        path,
        loadopt,
        adapter,
        column_collection: Optional[Any] = ...,
        parentmapper: Optional[Any] = ...,
        **kwargs
    ): ...
    class _SubqCollections(object):
        subq: Any = ...
        def __init__(self, subq) -> None: ...
        def get(self, key, default): ...
        def loader(self, state, dict_, row): ...
    def create_row_processor(
        self, context, path, loadopt, mapper, result, adapter, populators
    ): ...

class JoinedLoader(AbstractRelationshipLoader):
    join_depth: Any = ...
    def __init__(self, parent, strategy_key) -> None: ...
    def init_class_attribute(self, mapper): ...
    def setup_query(
        self,
        context,
        entity,
        path,
        loadopt,
        adapter,
        column_collection: Optional[Any] = ...,
        parentmapper: Optional[Any] = ...,
        chained_from_outerjoin: bool = ...,
        **kwargs
    ): ...
    def create_row_processor(
        self, context, path, loadopt, mapper, result, adapter, populators
    ): ...

def single_parent_validator(desc, prop): ...
