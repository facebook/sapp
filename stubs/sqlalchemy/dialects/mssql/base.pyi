from typing import Any, Optional

from ... import types as _sqltypes
from ...types import BIGINT as BIGINT
from ...types import BINARY as BINARY
from ...types import CHAR as CHAR
from ...types import DATE as DATE
from ...types import DATETIME as DATETIME
from ...types import DECIMAL as DECIMAL
from ...types import FLOAT as FLOAT
from ...types import INTEGER as INTEGER
from ...types import NCHAR as NCHAR
from ...types import NUMERIC as NUMERIC
from ...types import NVARCHAR as NVARCHAR
from ...types import SMALLINT as SMALLINT
from ...types import TEXT as TEXT
from ...types import VARCHAR as VARCHAR

class REAL(_sqltypes.REAL):
    __visit_name__: str = ...

class TINYINT(_sqltypes.Integer):
    __visit_name__: str = ...

class TIME(_sqltypes.TIME):
    __visit_name__: str = ...

class _DateTimeBase(object): ...

class SMALLDATETIME(_DateTimeBase, _sqltypes.DateTime):
    __visit_name__: str = ...

class DATETIME2(_DateTimeBase, _sqltypes.DateTime):
    __visit_name__: str = ...

class DATETIMEOFFSET(_sqltypes.TypeEngine[Any]):
    __visit_name__: str = ...
    def __init__(self, precision: Optional[int] = ..., **kwargs: Any) -> None: ...

class TIMESTAMP(_sqltypes._Binary):
    __visit_name__: str = ...
    def __init__(self, convert_int: bool = ...) -> None: ...

class ROWVERSION(TIMESTAMP):
    __visit_name__: str = ...

class NTEXT(_sqltypes.UnicodeText):
    __visit_name__: str = ...

class VARBINARY(_sqltypes.VARBINARY, _sqltypes.LargeBinary):
    __visit_name__: str = ...

class IMAGE(_sqltypes.LargeBinary):
    __visit_name__: str = ...

class XML(_sqltypes.Text):
    __visit_name__: str = ...

class BIT(_sqltypes.TypeEngine[int]):
    __visit_name__: str = ...

class MONEY(_sqltypes.TypeEngine[Any]):
    __visit_name__: str = ...

class SMALLMONEY(_sqltypes.TypeEngine[Any]):
    __visit_name__: str = ...

class UNIQUEIDENTIFIER(_sqltypes.TypeEngine[str]):
    __visit_name__: str = ...

class SQL_VARIANT(_sqltypes.TypeEngine[Any]):
    __visit_name__: str = ...
