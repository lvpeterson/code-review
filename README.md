# appsec code review scaffold

Point it at a codebase; it detects language(s) and framework(s), then runs a
framework-specific "deep dive" that extracts routes and runs baseline
IDOR/auth-coverage heuristics to point a human auditor at what to look at
first. Nothing here proves a vulnerability -- it's triage tooling.

## Usage

```
pip install -r requirements.txt
python main.py <target_path>
python main.py <target_path> --json report.json
python main.py <target_path> --language python --framework flask   # skip detection
```

## Layout

```
main.py                  CLI entry point
enumerator.py             detects language(s)/framework(s), dispatches to analyzers
core/
  models.py                Route / Finding / ScanResult dataclasses
  base.py                   BaseFrameworkAnalyzer -- every analyzer subclasses this
  registry.py                @register("language", "framework") decorator + lookup
  fsutil.py                   file-walking helpers shared by detectors/analyzers
  report.py                    console + JSON output
checks/                    framework-agnostic heuristics, operate on Route objects
  idor.py                    flags routes with id-like path params
  auth.py                    flags routes with no recognized auth decorator/middleware
languages/<lang>/
  detector.py               detect_language() / detect_framework() for that language
  <framework>_analyzer.py    route extraction + baseline checks for one framework
```

Currently implemented (route extraction + baseline checks):
- **python**: flask, fastapi, django
- **java**: spring
- **javascript**: express

Detection-only stubs (framework gets identified but analyzer returns empty +
a note -- fill these in following the pattern of an implemented one):
- **go**: net/http, gin
- **ruby**: rails, sinatra
- **dotnet**: aspnet

## Adding a new framework to an existing language

1. Create `languages/<lang>/<framework>_analyzer.py`, subclassing
   `BaseFrameworkAnalyzer` and implementing `find_routes()` +
   `run_baseline_checks()`. Decorate the class with
   `@register("<lang>", "<framework>")`.
2. Teach `languages/<lang>/detector.py`'s `detect_framework()` to recognize it.
3. Import the new module in `languages/<lang>/__init__.py`.

## Adding a new language

1. Create `languages/<newlang>/` with `detector.py` (`detect_language()` +
   `detect_framework()`) and one `<framework>_analyzer.py` per framework.
2. Add an `__init__.py` that imports the detector and every analyzer module
   (this is what triggers registration).
3. Import the new package in `languages/__init__.py` and add it to
   `LANGUAGE_MODULES` in `enumerator.py`.

## How route extraction works per language

Every implemented analyzer parses a real AST instead of pattern-matching
text -- this is what lets them tell "the class-level `@RequestMapping`" from
"a route", or find `@login_required` regardless of which line it's on
relative to the route decorator.

- **python** (`flask_analyzer.py`, `fastapi_analyzer.py`, `django_analyzer.py`):
  stdlib `ast` module, no dependency. Shared decorator/call-parsing helpers
  live in `languages/python/_ast_utils.py`.
- **java** (`spring_analyzer.py`): the `javalang` package -- a pure-Python
  Java parser, so no JDK/Node is required to run this.
- **javascript** (`express_analyzer.py`): `tree-sitter` with the
  `tree-sitter-javascript`/`tree-sitter-typescript` grammars -- prebuilt
  wheels, no Node.js or compiler required either.

The stub languages (go, ruby, dotnet) don't have a parser wired in yet.
Reasonable options when you get there: `go/ast` via a small Go helper
binary for Go, `tree-sitter-ruby`/`tree-sitter-c-sharp` (same tree-sitter
pattern as Express) for Ruby/.NET.

## Notes on the current heuristics

- `checks/auth.py` only knows about auth indicators you list per-analyzer
  (`KNOWN_AUTH_INDICATORS`) -- tune those to match each codebase's actual
  auth decorators/middleware names, or you'll get noisy false positives on
  intentionally-public routes.
- `checks/idor.py` only flags the presence of an id-like path param -- it
  doesn't (yet) inspect the handler body for an ownership check. That's the
  natural next thing to build now that route extraction is AST-precise.
- Express's `_ROUTER_OBJECT_NAMES` only recognizes variables literally named
  `app`/`router` -- it doesn't trace `const foo = express.Router()` to catch
  arbitrary variable names. Extend `_extract_route_call` if this codebase
  uses different naming.
