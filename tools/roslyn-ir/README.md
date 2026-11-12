# roslyn-ir

A small .NET 8 console tool that parses C# and VB.NET sources with Roslyn and
emits a JSON IR (schema 1) for the `dotnet_legacy` analyzer. The Python side
(`checks/dnl/`) drives it as a subprocess; this is the only C# code in the repo.

## Build

Requires the .NET 8 SDK. Cross-platform (Windows, Linux, macOS).

```
dotnet publish tools/roslyn-ir/src/RoslynIr.csproj -c Release -o tools/roslyn-ir/bin --nologo
```

This produces `tools/roslyn-ir/bin/roslyn-ir` (`roslyn-ir.exe` on Windows), a
framework-dependent build that needs the .NET 8 runtime. `tools/roslyn-ir/bin/`
and `src/bin/`, `src/obj/` are gitignored. The test suite builds it once per
session through the `roslyn_helper` fixture in `tests/conftest.py`. The scanner
finds it via the `CODE_REVIEW_ROSLYN_IR` environment variable, then
`tools/roslyn-ir/bin/`, then `PATH`. On first use with the SDK installed it
builds the helper automatically (a repo-local binary older than `src/` is
rebuilt). For a machine without the SDK, publish a self-contained single file
elsewhere and copy it (with `refs/`) to `tools/roslyn-ir/bin/`:

```
dotnet publish tools/roslyn-ir/src/RoslynIr.csproj -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o out
```

Roslyn packages: `Microsoft.CodeAnalysis.CSharp` and
`Microsoft.CodeAnalysis.VisualBasic`, both pinned to 4.11.0 -- bump them together.

`Microsoft.NETFramework.ReferenceAssemblies.net48` (1.0.3) is used only as
data: its `v4.8/*.dll` and `v4.8/Facades/*.dll` are copied flat into
`refs/net48/` next to the binary (build and publish output). The helper loads
them from `AppContext.BaseDirectory`, never from a Windows reference-assembly
path or the GAC, so semantic resolution works the same on Linux.

## CLI contract

- `roslyn-ir probe` -- parses, compiles and lowers one embedded C# and one
  embedded VB snippet (no target files), then writes `{"ok":true,"schema":1}` and exits 0. Any failure exits non-zero, including a missing or empty `refs/net48` (stderr says to republish).
- `roslyn-ir parse --input <request.json>` -- request:

  ```json
  {"root": "<abs dir>",
   "projects": [{"name": "Web", "language": "cs", "files": ["<abs>", "..."], "references": []}]}
  ```

  Writes JSON Lines to stdout, one object per file, in input order. A file that
  cannot be read or lowered yields `{"path": rel, "error": "<message>"}` and the
  run continues. stdout carries only JSON; diagnostics go to stderr.
  Each project is compiled once (its own files plus `refs/net48`); `references`
  (project-to-project) is accepted but ignored -- cross-project resolution is
  the Python model's job. If semantic lowering of a file throws, it is retried
  syntax-only before falling back to an error record.

Exit codes: 0 ok (even with per-file errors), 1 fatal (bad request, probe
failure), 2 usage.

## IR summary (schema 1)

- FileIR: `path` (relative to `root`, forward slashes), `language` (`cs`|`vb`),
  `project`, `parse_errors` (count of Roslyn error diagnostics), `types`.
- Type: `name`, `namespace`, `kind` (`class`|`interface`|`struct`|`module`|`enum`),
  `modifiers`, `bases` (simple names), `attributes`, `fields`, `properties`,
  `methods`, `line`, `end_line`. Nested types are flattened as `Outer.Inner`.
- Attr: `name` (qualifier and `Attribute` suffix stripped), `args`, `named`, `line`.
- Field: `name`, `type`, `line`, `init`, `is_const`. Enum members are const fields.
- Prop: `name`, `type`, `attributes`, `line`.
- Method: `name` (`.ctor` for constructors), `modifiers`, `return_type`
  (`void` for C# void and VB Sub, null for constructors), `params`,
  `attributes`, `handles` (VB `Handles`), `body`, `line`, `end_line`.
- Stmt `k`: `local`, `assign` (`op` is `=`, `+=`, `-=` or `concat=`; other
  compound ops lower to `=` with a `bin` value), `expr`, `return`, `throw`,
  `if`, `loop`, `try`, `using`, `with`, `other {text}`.
- Expr `k`: `lit`, `name`, `member`, `call`, `new`, `bin`, `interp`, `cond`,
  `index` (C# only), `cast`, `lambda`, `unknown {text}`.

Optional semantic keys (additive; omitted when the symbol does not resolve,
which is normal for third-party types):

- `call` and `member`: `sym` -- containing type full name + `.` + member name,
  for methods, properties, fields and events (e.g.
  `System.Data.SqlClient.SqlCommand.ExecuteReader`; extension methods name
  their static class, a VB default-property call names `Item`).
- `new`: `type_full` -- the created type.
- `local`: `type_full` -- the declared or inferred type (`var`, `Dim x = New ...`).

Type names are namespace-qualified with nesting as `Outer.Inner`, generic
arguments dropped (`System.Collections.Generic.List`) and arrays as `T[]` in
both languages. VB compilations get the standard template project imports
(`Microsoft.VisualBasic`, `System`, `System.Collections`,
`System.Collections.Generic`, `System.Data`, `System.Diagnostics`,
`System.Linq`, `System.Xml.Linq`), Option Strict Off, Option Infer On.

Every Stmt and Expr carries a 1-based `line` matching the original file.
Sources decode as UTF-8 (BOM stripped), falling back to Windows-1252.

Lowering notes worth knowing when consuming the IR:

- `this`/`Me`/`MyClass` -> `name this`; `base`/`MyBase` -> `name base`.
- VB `&` is `bin` op `concat`; other VB binary ops keep their source spelling
  (`=`, `<>`, `AndAlso`, ...), C# ops keep theirs (`==`, `&&`, ...).
- Inside a VB `With` block, `.Foo` lowers to `member` with `obj: null`.
- C# `switch` / VB `Select Case` lower to one flat `if` per section, `cond`
  being the governing expression; `lock`/`SyncLock`/`unsafe`/`checked`/`fixed`
  bodies are inlined; C# `using var x = ...;` wraps the rest of its block.
- `await`, parentheses and `!` (null-forgiving) are transparent.
- VB `x?.Y` lowers like C# (`member {obj: x, name: Y}`; the null check is dropped).
- Once the emitted JSON reaches 400 levels of nesting, the remaining syntax at
  that point degrades to a single `unknown`/`other` node whose text covers
  everything it replaces (for example the rest of an ElseIf chain, or the rest
  of a block after `using var`). Output never exceeds about 405 levels, so it
  stays loadable by Python's `json` and by recursive walkers.
