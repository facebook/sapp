# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from typing import NamedTuple, Optional, TypedDict


class ParsePosition(TypedDict, total=False):
    filename: str
    line: int
    start: int
    end: int


class SourceLocation(NamedTuple):
    """The location in a source file that an error occurred in

    If end_column is defined then we have a range, otherwise it defaults to
    begin_column and we have a single point.
    """

    line_no: int
    begin_column: int
    end_column: int

    @staticmethod
    def of(
        line_no: int, begin_column: int, end_column: Optional[int] = None
    ) -> "SourceLocation":
        return SourceLocation(line_no, begin_column, end_column or begin_column)

    def __str__(self) -> str:
        return SourceLocation.to_string(self)

    @staticmethod
    def from_typed_dict(d: ParsePosition) -> "SourceLocation":
        return SourceLocation(
            d["line"],
            d["start"],
            d["end"],
        )

    @staticmethod
    def from_string(location_string: str) -> "SourceLocation":
        location_points = location_string.split("|")
        assert len(location_points) == 3, "Invalid location string %s" % location_string
        return SourceLocation(*map(int, location_points))

    @staticmethod
    def to_string(location: "SourceLocation") -> str:
        return "|".join(
            map(str, [location.line_no, location.begin_column, location.end_column])
        )
