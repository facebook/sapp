from typing import Any, Optional
from pickle import Pickler, Unpickler

def Serializer(*args, **kw) -> Pickler: ...
def Deserializer(
    file,
    metadata: Optional[Any] = ...,
    scoped_session: Optional[Any] = ...,
    engine: Optional[Any] = ...,
) -> Unpickler: ...
def dumps(obj, protocol: int = ...) -> bytes: ...
def loads(
    data,
    metadata: Optional[Any] = ...,
    scoped_session: Optional[Any] = ...,
    engine: Optional[Any] = ...,
): ...
