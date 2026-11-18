# ASP.NET Core Final Plan: Combine, Coverage, Acceptance (Plan 4b of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Combine the three parallel ASP.NET Core branches (taint/XSS/object rules, configuration rules, SCA and carried-over families), prove every OWASP Web 2025 and API 2023 category is reachable for an ASP.NET Core target, accept the result on real open-source ASP.NET Core apps, and finish the documentation.

**Architecture:** One integration branch `feature/aspnetcore-final` is created from `feature/aspnetcore-taint` (which already contains the foundation) and the configuration and SCA branches are merged into it; conflicts are resolved toward "both sides' behaviour present" and generated artefacts (README coverage table) are regenerated rather than hand-merged. Coverage is enforced twice, as the spec's Decision 6 asks: statically through the inventory's DNL pass, and end to end through findings on synthetic fixture apps. Acceptance runs on public apps cloned into the session scratchpad only.

**Tech Stack:** Python 3.10+, pytest, Roslyn helper, git.

**Spec:** `docs/superpowers/specs/2026-11-14-aspnetcore-design.md` (Goals: every category reachable; Finding model and OWASP; Testing: acceptance; Decision 6). Inputs: Plan 1 `docs/superpowers/plans/2026-11-15-aspnetcore-foundation.md`, Plan 2 `docs/superpowers/plans/2026-11-16-aspnetcore-taint.md`, Plan 3 `docs/superpowers/plans/2026-11-16-aspnetcore-config.md`, Plan 4a `docs/superpowers/plans/2026-11-16-aspnetcore-sca-carried.md` (the last two arrive with their branches).

## Global Constraints

- Public repo: nothing committed (code, fixtures, tests, README, docs, commit messages) may name a client, engagement, target app (including the open-source apps used for acceptance), local path or user. Fixtures synthetic. Acceptance outputs and clones stay outside the repo.
- Prose and comments use `--`, never em-dashes.
- Tests: `.venv\Scripts\python -m pytest -q` from the repo root; the combined suite must pass on Windows and on Linux (Linux only when the Docker daemon is running; never start Docker Desktop from a task).
- No dotnet_legacy regression: the golden legacy baselines from Plan 4a and Plan 2's pinned legacy taint sets must still pass unchanged after the combine.
- A false "safe" is the worst outcome; noise is secondary. A merge that drops either side's check is a false "safe".
- Rule ids stay quoted literals; every id has a `core/owasp_web.RULES` entry and a row in `languages/dotnet_legacy/README.md`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No push. Merging the three branches into `feature/aspnetcore-final` happens only after the user approves it; merging anything into `main` is a separate user decision after this plan.

## Review Focus

1. A conflict in `languages/dotnet/analyzers.py` resolved by keeping one side's `guarded(...)` line and dropping the other's (test: every rule module from the three plans appears in `_code_results` and produces at least one finding on its own fixture after the combine, in Task 1).
2. The README coverage table regenerated from the combined inventory, not hand-merged (test: `tests/test_owasp_readme.py` passes on the combined tree, Task 1).
3. A category "covered" only by a rule that can never fire for ASP.NET Core (legacy-only code path imported by a shared module) (test: the end-to-end coverage test in Task 2 requires an actual finding per category on Core fixtures).
4. Acceptance findings that reveal a silent miss on real code (a route missing, an auth source misread) are fixed with a synthetic reduction test, not just noted (Task 3).
5. Docs that still mention "Plan N" or internal process after the docs pass (test: grep in Task 4).

---

### Task 1: Combine the branches

**Files:** whatever the merges touch; expected conflicts: `languages/dotnet/analyzers.py`, `languages/dotnet/detector.py`, `README.md` (coverage table and dotnet prose), `languages/dotnet/README.md`, `languages/dotnet_legacy/README.md` (DNL rule table rows), `core/owasp_web.py` (RULES entries), `tests/test_owasp_inventory_dnl.py`.

- [ ] **Step 1:** `git checkout -b feature/aspnetcore-final feature/aspnetcore-taint`; `git merge --no-ff <configuration branch>`; resolve conflicts keeping both sides' behaviour (both wiring lines, both rule rows, both README sections merged into one coherent section per topic); regenerate the README coverage table from `tests/owasp_inventory.coverage_rows(RULES)`. Commit the merge.
- [ ] **Step 2:** `git merge --no-ff <SCA/carried branch>`; same rules. Commit.
- [ ] **Step 3: Write the failing test** `tests/test_dotnet_combined.py::test_every_rule_module_is_wired`: every rule module imported by `languages/dotnet/analyzers.py` is called in `_code_results` (static AST check), and the list includes `rules_auth_core`, `rules_taint`, `rules_xss`, `rules_object`, the configuration modules from Plan 3, `rules_sca_core` (or Plan 4a's name) and the carried families from Plan 4a. Run it; it passes only if the merge kept every line.
- [ ] **Step 4: Run the full suite** (expect the three branches' test counts combined, minus duplicates). Fix only merge breakage here; behaviour changes belong to later tasks.
- [ ] **Step 5: Commit** `test(dotnet): combined ASP.NET Core branches wire every rule module`

### Task 2: Every OWASP category reachable for ASP.NET Core

**Files:** Create `tests/test_dotnet_owasp_coverage.py`; Modify `tests/owasp_inventory.py` only if the DNL pass needs the new modules; add synthetic fixture cases under `tests/fixtures/aspnetcore/` only where a category has no Core finding yet.

- [ ] **Step 1: Write the failing tests:**
  - `test_static_dotnet_row_covers_everything`: the `dotnet` row from `coverage_rows(RULES)` has `none` in both gap columns (Web 2025 A01-A10 and API 2023 API1-API10).
  - `test_end_to_end_every_category_on_core_fixtures`: running `enumerate_target` with the helper over every app under `tests/fixtures/aspnetcore/` yields `dotnet` findings whose OWASP tags cover all of A01-A10 (2025) and API1-API10 (2023); on failure the message names each missing category and the rule ids mapped to it.
  - `test_degraded_categories`: the same without the helper, minus an explicit, commented list of categories that need the helper (each with the reason); the list may be empty.
- [ ] **Step 2: Run to verify** -- they fail if any category is missing. For each missing category: add a synthetic fixture case that exercises an existing rule; if no rule can produce the category for Core, stop and report it (that is a spec gap, decided by the user).
- [ ] **Step 3: Run the full suite.** Commit `test(dotnet): every OWASP Web 2025 and API 2023 category reachable for ASP.NET Core`.

### Task 3: Acceptance on real open-source ASP.NET Core apps

**Files:** fixes as needed in `checks/dnl/*` with synthetic reduction tests; no target names anywhere in the repo.

- [ ] **Step 1:** Clone three or four public, permissively licensed ASP.NET Core apps covering the three styles (one controllers-based API, one Razor Pages app, one minimal-API app, ideally one with Identity) into the session scratchpad with `--depth 1`. Record their names, commits and licences only in the task report (scratch), never in the repo.
- [ ] **Step 2:** Scan each with the helper and with `--allow-degraded` forced (monkeypatched helper discovery in a small scratch script), JSON + HTML outputs to the scratchpad; record wall time.
- [ ] **Step 3:** Triage: for every route check it is listed with the right style and auth source (spot-check at least 20 routes per app against the source); for every high/medium finding decide true positive / false positive / REVIEW-correct; list any construct the engine missed silently.
- [ ] **Step 4:** For each silent miss or wrong auth source: reduce it to a synthetic fixture case, write the failing test, fix, verify. Noise fixes only when cheap and safe.
- [ ] **Step 5:** Full suite; commit `fix(dnl): acceptance fixes from real ASP.NET Core apps` (generic message; no app names).

### Task 4: Documentation, Linux run

**Files:** `README.md`, `languages/dotnet/README.md`, `languages/dotnet_legacy/README.md`, `tools/roslyn-ir/README.md` if needed.

- [ ] **Step 1:** Rewrite `languages/dotnet/README.md` as one coherent document (frameworks, what is analysed, helper requirement and degraded mode, auth states and sources, taint/XSS/object rules, configuration rules, SCA, carried families, OWASP mapping pointer, Known limits merged from all plans). Update the root README dotnet sections. No "Plan N" wording, no internal process terms.
- [ ] **Step 2:** `git grep -n -i "plan [1-4]\|ledger\|subagent"` over README files and `languages/` returns nothing user-facing; `test_readme_lists_every_rule_with_tags` and `test_owasp_readme` pass.
- [ ] **Step 3:** Linux container run if the daemon is up (report state either way).
- [ ] **Step 4:** Scrub `git diff main` and `git log main..HEAD` for target/client names, local paths, person names. Commit `docs(dotnet): ASP.NET Core support documented end to end`.
