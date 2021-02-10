from typing import Any, Optional
from .interfaces import MapperOption
from ..sql.base import Generative

class Load(Generative, MapperOption):
    path: Any = ...
    context: Any = ...
    local_opts: Any = ...
    def __init__(self, entity) -> None: ...
    @classmethod
    def for_existing_path(cls, path): ...
    is_opts_only: bool = ...
    strategy: Any = ...
    propagate_to_loaders: bool = ...
    def process_query(self, query): ...
    def process_query_conditionally(self, query): ...
    def set_relationship_strategy(
        self, attr, strategy, propagate_to_loaders: bool = ...
    ): ...
    def set_column_strategy(
        self, attrs, strategy, opts: Optional[Any] = ..., opts_only: bool = ...
    ): ...

class _UnboundLoad(Load):
    path: Any = ...
    local_opts: Any = ...
    def __init__(self) -> None: ...

class loader_option(object):
    def __init__(self) -> None: ...
    name: str = ...
    fn: Any = ...
    def __call__(self, fn): ...

def contains_eager(loadopt, attr, alias: Optional[Any] = ...): ...
def load_only(loadopt, *attrs): ...
def joinedload(loadopt, attr, innerjoin: Optional[Any] = ...): ...
def joinedload_all(*keys, **kw): ...
def subqueryload(loadopt, attr): ...
def subqueryload_all(*keys): ...
def lazyload(loadopt, attr): ...
def lazyload_all(*keys): ...
def immediateload(loadopt, attr): ...
def noload(loadopt, attr): ...
def raiseload(loadopt, attr, sql_only: bool = ...): ...
def defaultload(loadopt, attr): ...
def defer(loadopt, key): ...
def undefer(loadopt, key): ...
def undefer_group(loadopt, name): ...
