# roslyn-ir

A small .NET 8 console tool that parses C# and VB.NET sources with Roslyn and
emits a JSON IR (schema 2) for the `dotnet_legacy` analyzer. The Python side
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

A second profile, `netcore`, serves SDK-style ASP.NET Core projects. The
`Microsoft.NETCore.App.Ref` and `Microsoft.AspNetCore.App.Ref` packages (both
pinned to `[8.0.11]`) are DotnetPlatform packages, so the csproj uses
`PackageDownload` (a `PackageReference` fails with NU1213) and copies
`ref/net8.0/*.dll` from the NuGet cache (lower-case package folders) flat into
`refs/netcore/` next to the binary. The SDK's own `packs/` folder is never used.

## CLI contract

- `roslyn-ir probe` -- parses, compiles and lowers one embedded C# and one
  embedded VB snippet (no target files), plus one ASP.NET Core snippet compiled with the `netcore` profile, then writes `{"ok":true,"schema":2}` and exits 0. Any failure exits non-zero, including a missing or empty `refs/net48` or `refs/netcore` (stderr names the folder and says to republish).
- `roslyn-ir parse --input <request.json>` -- request:

  ```json
  {"root": "<abs dir>",
   "projects": [{"name": "Web", "language": "cs", "files": ["<abs>", "..."], "references": []}]}
  ```

  A project may also carry `"imports": ["System.Data.SqlClient", ...]` (VB
  only): extra global imports added to the template defaults, for namespaces a
  `.vbproj` imports project-wide. Invalid entries are skipped.

  A project may also carry `"refs": "net48" | "netcore"` (default `"net48"`;
  an unknown name falls back to `net48` with a stderr warning) choosing the
  reference-assembly folder, and `"global_usings": ["Microsoft.AspNetCore.Http", ...]`
  (C# only): namespaces compiled as `global using` directives, standing in for
  an SDK project's implicit usings.

  Writes JSON Lines to stdout, one object per file, in input order. A file that
  cannot be read or lowered yields `{"path": rel, "error": "<message>"}` and the
  run continues. stdout carries only JSON; diagnostics go to stderr.
  Each project is compiled once (its own files plus the selected `refs/net48` or `refs/netcore` profile); `references`
  (project-to-project) is accepted but ignored -- cross-project resolution is
  the Python model's job. If semantic lowering of a file throws, it is retried
  syntax-only before falling back to an error record.

Exit codes: 0 ok (even with per-file errors), 1 fatal (bad request, probe
failure), 2 usage.

## IR summary (schema 2)

- FileIR: `path` (relative to `root`, forward slashes), `language` (`cs`|`vb`),
  `project`, `parse_errors` (count of Roslyn error diagnostics), `types`.
- Type: `name`, `namespace`, `kind` (`class`|`interface`|`struct`|`module`|`enum`),
  `modifiers`, `bases` (simple names), `attributes`, `fields`, `properties`,
  `methods`, `line`, `end_line`. Nested types are flattened as `Outer.Inner`.
- Attr: `name` (qualifier and `Attribute` suffix stripped), `args`, `named`, `line`.
- Field: `name`, `type`, `line`, `init`, `is_const`. Enum members are const fields.
- Prop: `name`, `type`, `attributes`, `line`, and optional `get` / `set` (Stmt
  lists) when an accessor has a body or expression body; auto-properties omit
  both. C# `=> expr` lowers as `get: [return expr]`; the C# setter value is
  `name value` and the VB setter parameter keeps its declared name (`init`
  accessors count as `set`). VB properties with a `Set` block also carry
  `set_param`, the setter's value parameter name (default `Value`).
  A property with an initializer (C# `{ get; set; } = expr`, VB `Property X As T = expr` or
  `As New T(..)`) also carries `init` (Expr), like a field.
- Method: `name` (`.ctor` for constructors), `modifiers`, `return_type`
  (`void` for C# void and VB Sub, null for constructors), `params` (each
  `{name, type, attributes}` plus an optional lowercased `modifiers` list when
  the parameter has any: C# `this`, `params`, `ref`, `out`, `in`; VB `byref`,
  `byval`, `paramarray`, `optional`),
  `attributes`, `handles` (VB `Handles`), `implements` (VB method-level `Implements` targets, or the C# explicit interface
  implementation, as `IFoo.Bar`), `body`, `line`, `end_line`.
- Generic names: a `name` or `member` Expr built from a generic name (`MapHub<ChatHub>`,
  `UseStartup<Startup>`) also carries `targs`, the type arguments as written
  (`["ChatHub"]`); `name` / `id` stay the bare identifier. The key is absent for non-generic names.
- Synthetic top-level type: a C# file with top-level statements gets one extra type
  written before the declared ones: `Program` (namespace empty, modifiers `static`,
  `partial`) with a single static method `<Main>$` (`void`, no params) whose `body` is
  the lowered statements and whose `line` / `end_line` span them. A hand-written
  `partial class Program` in the same file stays a separate type record.
- Primary constructors: a class, struct or record with a parameter list gets a `.ctor`
  method (first in `methods`, no modifiers, null `return_type`, those `params`); a
  `: Base(args)` in the base list becomes its leading `base(args)` call statement.
  Positional record parameters also become properties (`{name, type, attributes, line}`,
  no accessors), except those the record body declares itself.
- Stmt `k`: `local`, `assign` (`op` is `=`, `+=`, `-=` or `concat=`; other
  compound ops lower to `=` with a `bin` value), `expr`, `return`, `throw`,
  `if`, `loop`, `try`, `using`, `with`, `other {text}`.
- Expr `k`: `lit`, `name`, `member`, `call`, `new`, `bin`, `interp`, `cond`,
  `index` (C# only), `cast`, `lambda`, `unary {op, e}`, `unknown {text}`.
  `lambda {body, params?, param_info?, end_line}`: `body` is an Expr or a Stmt list,
  `params` the lowered parameter names and `param_info` one `{name, type, attributes,
  modifiers}` per parameter (`type` null when implicit, `modifiers` lowercased, possibly
  empty); both omitted when there are no parameters. `end_line` is the lambda's last line
  and is always present. A local function lowers as a `local` whose `init` is a lambda.
  Modern C# shapes (all syntactic, so identical with or without a reference profile):
  a collection expression `[a, ..b]` is an untyped `new` (`type` null, no `args`) whose
  `init` entries are the elements (a spread contributes its inner expression); a switch
  expression is nested `cond` (`c` the governing expression, `t` an arm value, `f` the
  remaining arms, the last arm contributing just its value; guards are dropped); an
  `is` pattern is `bin {op: "is"}` whose right side is `unknown {text}` holding the
  pattern (a plain `x is Type` keeps the type as an Expr); `x with { A = 1 }` is an
  untyped `new` whose `args` is `[x]` and whose `init` entries are the assignments. A raw
  string literal is a `lit` with the indentation of its closing line removed.
  `unary` ops: C# `!`, `-`, `~`, `++`, `--` (prefix and postfix alike), VB `Not`, `-`;
  a negated numeric literal still folds to a `lit`.

Optional semantic keys (additive; omitted when the symbol does not resolve,
which is normal for third-party types):

- `call` and `member`: `sym` -- containing type full name + `.` + member name,
  for methods, properties, fields and events (e.g.
  `System.Data.SqlClient.SqlCommand.ExecuteReader`; extension methods name
  their static class, a VB default-property call names `Item`).
- `index` (C#): `sym` -- the indexer's containing type + `.Item` (e.g.
  `System.Collections.Specialized.NameValueCollection.Item`); arrays have none.
- `name`: `sym` -- containing type + `.` + member, only when the identifier binds
  to a field or property (e.g. a WebForms designer field `MyPage.txtName`);
  locals, parameters, types and namespaces get none.
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

- VB `AddressOf Handler` lowers to the operand itself (a `name` / `member` reference), like a C# method group.
- `this`/`Me`/`MyClass` -> `name this`; `base`/`MyBase` -> `name base`.
- VB `&` is `bin` op `concat`; other VB binary ops keep their source spelling
  (`=`, `<>`, `AndAlso`, ...), C# ops keep theirs (`==`, `&&`, ...).
- Inside a VB `With` block, `.Foo` lowers to `member` with `obj: null`.
- C# `switch` / VB `Select Case` lower to one flat `if` per section, `cond`
  being the governing expression; `lock`/`SyncLock`/`unsafe`/`checked`/`fixed`
  bodies are inlined; C# `using var x = ...;` wraps the rest of its block.
- `await`, parentheses and the C# null-forgiving `!` suffix are transparent (a
  prefix `!x` is a `unary`).
- VB `x?.Y` lowers like C# (`member {obj: x, name: Y}`; the null check is dropped).
- Once the emitted JSON reaches 400 levels of nesting, the remaining syntax at
  that point degrades to a single `unknown`/`other` node whose text covers
  everything it replaces (for example the rest of an ElseIf chain, or the rest
  of a block after `using var`). Output never exceeds about 405 levels, so it
  stays loadable by Python's `json` and by recursive walkers.
