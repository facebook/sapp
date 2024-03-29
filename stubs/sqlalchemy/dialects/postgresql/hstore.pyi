from typing import Any, List, Mapping, Optional, Text, Type

from ... import types as sqltypes
from ...sql import functions as sqlfunc
from ...sql import type_api
from .array import ARRAY

class HSTORE(
    sqltypes.Indexable, sqltypes.Concatenable, sqltypes.TypeEngine[Mapping[str, Any]]
):
    __visit_name__: str = ...
    hashable: bool = ...
    text_type: type_api.TypeEngine[Text] = ...
    def __init__(
        self, text_type: Optional[type_api.TypeEngine[Text]] = ...
    ) -> None: ...
    class Comparator(type_api.TypeEngine.Comparator):
        def has_key(self, other: Any): ...
        def has_all(self, other: Any): ...
        def has_any(self, other: Any): ...
        def contains(self, other: Any, **kwargs: Any): ...
        def contained_by(self, other: Any): ...
        def defined(self, key: Any) -> _HStoreDefinedFunction: ...
        def delete(self, key: Any) -> _HStoreDeleteFunction: ...
        def slice(self, array: Any) -> _HStoreSliceFunction: ...
        def keys(self) -> _HStoreKeysFunction: ...
        def vals(self) -> _HStoreValsFunction: ...
        def array(self) -> _HStoreArrayFunction: ...
        def matrix(self) -> _HStoreMatrixFunction: ...
    comparator_factory: Type[HSTORE.Comparator] = ...
    def bind_processor(self, dialect: Any): ...
    def result_processor(self, dialect: Any, coltype: Any): ...

class hstore(sqlfunc.GenericFunction[Mapping[str, Any]]):
    type: HSTORE = ...
    name: str = ...

class _HStoreDefinedFunction(sqlfunc.GenericFunction[bool]):
    type: sqltypes.Boolean = ...
    name: str = ...

class _HStoreDeleteFunction(sqlfunc.GenericFunction[Mapping[str, Any]]):
    type: HSTORE = ...
    name: str = ...

class _HStoreSliceFunction(sqlfunc.GenericFunction[Mapping[str, Any]]):
    type: HSTORE = ...
    name: str = ...

class _HStoreKeysFunction(sqlfunc.GenericFunction[List[Text]]):
    type: ARRAY[Text] = ...
    name: str = ...

class _HStoreValsFunction(sqlfunc.GenericFunction[List[Text]]):
    type: ARRAY[Text] = ...
    name: str = ...

class _HStoreArrayFunction(sqlfunc.GenericFunction[List[Text]]):
    type: ARRAY[Text] = ...
    name: str = ...

class _HStoreMatrixFunction(sqlfunc.GenericFunction[List[Text]]):
    type: ARRAY[Text] = ...
    name: str = ...
