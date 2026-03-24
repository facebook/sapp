# SAPP Architecture Reference

Deep reference for AI agents working in the SAPP codebase. Read CLAUDE.md first for orientation. Note: `facebook/` paths refer to Meta-internal extensions not included in the OSS release.

## System Overview

SAPP is a **post-processor** for static taint analysis tools (Pysa, Zoncolan, Angliru, Fontainebleau, Mariana Trench). It transforms raw JSON output into a queryable database with web UI and CLI.

Four layers: **Rust Parsers** (JSON → parse types, 64-thread PyO3 bridge) → **Python Pipeline** (chain of `PipelineStep[T_in, T_out]`) → **SQLAlchemy ORM** (Issue, Run, TraceFrame, SharedText) → **UI** (OSS: Flask+GraphQL+React; Internal: Hack/React).

Separately, **Local Flow Explorer** (`facebook/local_flow/`) queries intra-procedural data flow graphs with its own SQLite DB and `.lf` query language.

## Data Model

A **taint issue** is a data flow from a **source** (user input) to a **sink** (SQL query) through function calls. Each has:
- **Code** — rule number (e.g., 5001 = XSS)
- **Handle** — stable dedup key surviving reformats
- **Preconditions/Postconditions** — trace frames backward to sources / forward to sinks
- **Features** — breadcrumbs from analysis (e.g., `via:urllib.parse.unquote`)

A **trace frame** = one step: caller/callee + ports + leaves (terminal sources/sinks with distance).

### Database Schema (`sapp/models.py`)

```
Run                    — one analysis run (branch, commit, timestamp)
 └─ IssueInstance      — one occurrence of an issue in a run
     ├─ Issue          — deduplicated across runs (by handle)
     ├─ TraceFrame     — one frame in pre/postcondition trace
     │   ├─ TraceFrameLeafAssoc    — links frame to leaf (kind + depth)
     │   └─ TraceFrameAnnotation   — extra frame metadata
     └─ SharedText     — deduplicated strings (features, messages, source/sink names)
```

Key design: `SharedText` is one table for all strings, discriminated by `SharedTextKind`. `DBID`/`PrimaryKeyGenerator` manages IDs for batch inserts. `TraceKind` enum: `PRECONDITION` or `POSTCONDITION`.

## Pipeline Deep Dive

### Framework (`pipeline/__init__.py`)

```python
class PipelineStep(Generic[T_in, T_out], metaclass=ABCMeta):
    @abstractmethod
    def run(self, input: T_in, summary: Summary,
            scoped_metrics_logger: ScopedMetricsLogger) -> Tuple[T_out, Summary]: ...
```

Default chain (assembled in `cli_lib.py`):
```
Parser → CreateDatabase → AddFeatures → ModelGenerator → TrimTraceGraph → DatabaseSaver
```

### Parse Types

NamedTuples that flow between steps:

- **`ParseIssueTuple`** — code, message, callable, handle, filename, line, preconditions, postconditions, initial_sources, final_sinks, features, fix_info
- **`ParseConditionTuple`** — type (PRE/POST), caller, caller_port, callee, callee_port, callee_location, leaves, features, titos, annotations
- **`Frames`** = `Dict[FrameKey, List[ParseConditionTuple]]` where `FrameKey = (caller, caller_port)`
- **`IssuesAndFrames`** — issues (generator), preconditions (Frames), postconditions (Frames)

All parse types have `.interned()` for `sys.intern()` on repeated strings.

### Pipeline Steps

| Step | Input → Output | Purpose |
|------|---------------|---------|
| `Parser` | `AnalysisOutput → IssuesAndFrames` | Streams JSON via generator, collects Frames |
| `CreateDatabase` | `IssuesAndFrames → IssuesAndFrames` | Creates tables (pass-through) |
| `AddFeatures` | `IssuesAndFrames → IssuesAndFrames` | Appends user-specified features |
| `ModelGenerator` | `IssuesAndFrames → TraceGraph` | Converts tuples to ORM models, deduplicates |
| `TrimTraceGraph` | `TraceGraph → TraceGraph` | Removes unreachable trace frames |
| `DatabaseSaver` | `TraceGraph → None` | Bulk-writes via BulkSaver |

Additional conditional steps: `WarningCodeFilter`, `IssueCallableFilter`, `IssueHandleFilter`, `PropagateContextToLeafFrames`, `PropagateToCrtexAnchors`, `AddReverseTraces`, `MetaRunIssueDuplicateFilter`.

### Parser Architecture

`BaseParser` uses a **generator pattern**: `parse_issues_and_collect_frames()` yields `ParseIssueTuple`s one at a time (memory-efficient), accumulates Frames internally, returns them via `StopIteration.value`.

Concrete parsers implement `parse_raw(input) → Iterable[Dict]` and `parse_issue(raw) → ParseIssueTuple`.

### Rust Parser Bridge (`facebook/lib/`)

```
Python                               Rust
─────                                ────
start_pysa_parser(paths, repo_dirs)  → ThreadPool(64) + file parsing
parser.get_issue_batch()             → Drains sync_channel → batch (None = done)
parser.get_preconditions()           → Returns Frames from DashMap
parser.get_postconditions()          → Returns Frames from DashMap
```

The `.pyi` stub is the **authoritative API contract**. Key files: `sapp_rs_lib.rs` (PyO3 module), `parsers/pysa_parser.rs`, `parsers/mariana_trench_parser.rs`, `parsers/zoncolan_parser.rs`, `parsers/interner.rs` (string dedup).

Cross-language tests (`test_*_rust_parser.py`) verify Rust output matches Python parsers.

## Local Flow Explorer (`facebook/local_flow/`)

Separate Rust system for **intra-procedural** data flow queries (within a single function).

Key modules: `types` (FlowNode with 7 variants, Direction), `loader` (LoadGraph + SqliteLoader), `closure` (parallel transitive closure via rayon), `search` (query execution), `query_parser` (1,290-line recursive descent parser for `.lf` DSL), `cache` (LRU), `gerth_automaton` (LTL model checking).

The `.lf` files in `local_flow_explorer/scripts/` are executable query examples. No formal grammar spec — read the parser.

## CRTEX (`facebook/taint_exchange/`)

Cross-repo taint exchange. Command pattern: `crtex.py` dispatches to `crtex_commands/` (create, read, write, drop, schema, transform). Config in `crtex_config/` with JSON schema validation.

## Performance Notes

- **String interning** (Python `sys.intern()`, Rust `InternedString`) — critical for memory at scale
- **Generator pattern** in parsers — streams issues instead of materializing all
- **BulkSaver** — batched DB writes to avoid per-row INSERT overhead
- **Frames `dispose()` pattern** — explicitly freed after pipeline processing, before DB writes
