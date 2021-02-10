from typing import Any, Optional
from . import visitors

join_condition: Any = ...

def find_join_source(clauses, join_to): ...
def visit_binary_product(fn, expr): ...
def find_tables(
    clause,
    check_columns: bool = ...,
    include_aliases: bool = ...,
    include_joins: bool = ...,
    include_selects: bool = ...,
    include_crud: bool = ...,
): ...
def unwrap_order_by(clause): ...
def unwrap_label_reference(element): ...
def expand_column_list_from_order_by(collist, order_by): ...
def clause_is_present(clause, search): ...
def surface_selectables(clause): ...
def surface_column_elements(clause): ...
def selectables_overlap(left, right): ...
def bind_values(clause): ...
def adapt_criterion_to_null(crit, nulls): ...
def splice_joins(left, right, stop_on: Optional[Any] = ...): ...
def reduce_columns(columns, *clauses, **kw): ...
def criterion_as_pairs(
    expression,
    consider_as_foreign_keys: Optional[Any] = ...,
    consider_as_referenced_keys: Optional[Any] = ...,
    any_operator: bool = ...,
): ...

class ClauseAdapter(visitors.ReplacingCloningVisitor):
    __traverse_options__: Any = ...
    selectable: Any = ...
    include_fn: Any = ...
    exclude_fn: Any = ...
    equivalents: Any = ...
    adapt_on_names: Any = ...
    def __init__(
        self,
        selectable,
        equivalents: Optional[Any] = ...,
        include_fn: Optional[Any] = ...,
        exclude_fn: Optional[Any] = ...,
        adapt_on_names: bool = ...,
        anonymize_labels: bool = ...,
    ) -> None: ...
    def replace(self, col): ...

class ColumnAdapter(ClauseAdapter):
    columns: Any = ...
    adapt_required: Any = ...
    allow_label_resolve: Any = ...
    def __init__(
        self,
        selectable,
        equivalents: Optional[Any] = ...,
        chain_to: Optional[Any] = ...,
        adapt_required: bool = ...,
        include_fn: Optional[Any] = ...,
        exclude_fn: Optional[Any] = ...,
        adapt_on_names: bool = ...,
        allow_label_resolve: bool = ...,
        anonymize_labels: bool = ...,
    ) -> None: ...
    def wrap(self, adapter): ...
    def traverse(self, obj): ...
    adapt_clause: Any = ...
    adapt_list: Any = ...
