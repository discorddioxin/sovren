# Sovren Audit — Session Log: Phase 4 (Architecture) & Phase 5 (Testing Strategy)

| | |
|---|---|
| **Session** | Audit of `discorddioxin/sovren`, per `docs/AUDIT-ROADMAP.md` — continuation of `findings-phase0-phase1.md` and `findings-phase2-phase3.md` |
| **Freeze commit** | `003149e12777f19a3da2433066ddf3f1303da147` (unchanged) |
| **Environment** | Linux 6.1.158+ x86-64 (e2b sandbox), 2026-10-18; working copy `/tmp/sovren-audit` |
| **Ground-rule compliance** | Read-only on the repo; all analysis scripts ran from `/tmp`; `git status` clean of tracked changes |
| **Citation rule** | Every claim cites a repository location (`file:line`) or an external authority, listed in §5 |

---

## 1. New findings

| ID | Sev | Component | Title | Design intent? | Invariant |
|---|---|---|---|---|---|
| F-36 | Info+ | library/sha1.sov | SHA-1 ships with an explicit "NOT for security" header — the honesty invariant applied to a deprecated primitive | deliberate | I5 ✓ |
| F-37 | P3 | .github/workflows | All five action uses are tag-pinned (`@v4`), not commit-SHA-pinned | accidental | — |
| F-38 | P2 | library | **225 of 2,023 tasks (11%) in live libraries are referenced nowhere** — no test, no internal caller | accidental | — |
| F-39 | P3 | library/x86.sov, arm.sov | 20 core tasks referenced nowhere, incl. **6 implemented-but-unreachable SSE/AVX emulator handlers** | unknown | — |
| F-40 | P3 | library/assert.sov, test.sov | The language's own unit-test affordances are unused by the project's battery (and are themselves orphans) | accidental | I8 |
| F-41 | Info+ | compiler cores | Global-state map is small and purposeful: 10 shared-mutable globals in cx86, 2–4 per target layer — H14 largely refuted at the feared scale | deliberate | — |
| F-42 | Info+ | tests/fast.sov | Skip-list governance is sound: 14 skips, each justified in-header; new checks auto-run in both tiers | deliberate | I5 ✓ |
| F-43 | P2 | library/arm.sov | ARM differential-vector gap, quantified: no vector suite counterpart; 4 ARM emulator helpers unreferenced | accidental | — |
| F-44 | P2 | library/suite.sov | Size concentration: the four largest files (cx86 315 KB, x86 304 KB, suite 178 KB, carm 121 KB); suite decomposition proposal | accidental | I1 |
| F-45 | Info+ | compilers | Hook contract consistent across the three x86 back ends (same five core-facing tasks) | deliberate | I3 ✓ |
| F-46 | — | tests | Test-asset inventory and oracle classification (deliverable, §2) | — | — |
| F-47 | P2 | tests | Coverage proxy + nightly mutation gate proposed (pilot already proves 2/2 mutants survive — F-35) | — | I8 |

### F-36 — Info+ · SHA-1 is honestly labeled

`library/sha1.sov:1` — "SHA-1 (legacy checksums, NOT for security)". The roadmap's Phase 2 item ("file as *deprecated primitive reachable by default*") resolves as **already satisfied by design**: the header carries the warning, the library is opt-in (`use sha1`), and its only consumers are the suite and the arm64 test (both as vector subjects). No finding; recorded as a positive instance of I5.

### F-37 — P3 · CI actions are tag-pinned, not SHA-pinned

**Evidence:** all five `uses:` lines pin floating tags — `.github/workflows/check.yml:18, 273, 314, 335` and `.github/workflows/legacy.yml:14`, all `actions/checkout@v4`. A moved or compromised tag silently swaps the checkout action. [SLSA Build Track L3 requires pinned dependencies; OpenSSF Scorecard, "Pinned-Dependencies" check.]

**Suggested fix:** pin each to the full commit SHA (`actions/checkout@<40-hex>`). **Acceptance:** `grep "uses:" .github/workflows/*.yml` shows only SHA-pinned refs. **Wave 1** (five-line change, high value/effort ratio).

### F-38 — P2 · 225 library tasks (11%) are referenced nowhere in the project

**Evidence:** whole-repo word-boundary reference sweep over all 328 `.sov` files: of 2,023 top-level library tasks, **225 in live libraries** (e.g., `bi_add`, `bi_pow2`, `b64_decode`, `bf_read`, `bit_or`, `arr_new`, `arg_has`) are never referenced by any file other than their own definition — no internal caller, no test. A further 159 sit in the 60 orphan libraries (F-32). For a standard library, unreferenced ≠ removable (it is public API surface), but it **ships unverified**: no check in the 551-check battery exercises it. Counts are conservative — comment mentions count as references. [Roadmap Phase 4 "dead code sweep"; testing-maturity literature on unverified API surface.]

**Suggested fix:** (a) extend the suite's `tr_every_lib_checks` from build-only to build-and-run for the highest-value API tasks; (b) mark intentionally-unused API with a header note (I5 honesty). **Wave 2.**

### F-39 — P3 · 20 core tasks referenced nowhere, including 6 SSE/AVX handlers

**Evidence:** the same sweep over the compiler/emulator cores (`cx86`, `carm`, `x86`, `arm`, six per-target compilers; 873 tasks) finds 20 unreferenced. The notable class: **six SSE/AVX instruction handlers in `library/x86.sov` — `x_w_pminuw`, `x_w_pminud`, `x_w_pabsw`, `x_w_vpermilps`, `x_w_vpermilpd`, `x_vminmax`** — appear nowhere, including in the decoder's dispatch (a name-based dispatch would reference them). Either they are dead code, or the decoder lacks the wiring to reach them — in both cases they are **untested**. Also unreferenced: `arm_why`, `arm_low`, `arm_result`, `arm_run_symbol` (the ARM emulator's result-inspection helpers — consistent with the ARM differential gap, F-43), and `x86_used_syscall` (a helper that would answer "did this guest touch a syscall?" — unused). **Design intent: unknown** — needs a maintainer call before any removal.

**Suggested fix:** if the SSE handlers are meant to be reachable, wire the decoder and add differential vectors; if not, delete or mark them. **Wave 3.**

### F-40 — P3 · The language's own test affordances are unused by its own battery

**Evidence:** `library/assert.sov` and `library/test.sov` are never `use`d by any file (grep over the repo; both are on the F-32 orphan list). The project's battery instead rolls its own machinery (`library/testrun.sov`, `tr_ok`/`tr_bad`). Consequence: the shipped unit-testing libraries are themselves untested, and newcomers see no in-tree example of the intended unit-testing style. [I8 dogfooding.]

**Suggested fix:** either dogfood `assert.sov` inside the suite's per-library checks, or document in `testrun.sov`'s header why the bespoke machinery exists. **Wave 3.**

### F-41 — Info+ · Global-state map: small and purposeful (H14 largely refuted)

**Evidence:** declaration/mutation scan of the cores — `library/cx86.sov`: 30 top-level declarations, **10 shared-mutable globals** (mutated by >1 task), dominated by the branch-bookkeeping family `bk/bi/bj/bs/be` (2 tasks each); `library/carm.sov`: 6; target layers: linux 2 (`fn_names`, `fn_offs` — the function table shared by `compile`/`copyargs`/`emit_write_lit`), windows 4, macos 3. The generic names that look alarming (`i` mutated by 36 tasks, `n` by 22) are **task-locals**, fresh per call — recursion correctness (fib(30) = 832040, Phase 3) proves per-call frames work. The single-pass discipline keeps shared state minimal; the 10 cx86 globals are the real constraint on any future parallel-pass work. [H14 refuted at the feared scale; residual documented.]

### F-42 — Info+ · Skip-list governance is sound

**Evidence:** `tests/fast.sov` lists exactly 14 skips, each with an in-header justification (emulator-heavy guests = 60 of the 105 s; byte-freshness rebuilds already proven harder by bootstrap), and the header states the self-maintaining property: "a check added to `library/suite.sov` runs in both tiers the day it is written" — verified structurally: `fast.sov` sets `tr_skips` and calls the same `suite()` job as `all.sov` (`fast.sov:36-39`). CI runs the full tier on every push regardless. [H15 partially refuted: governance is good; the monolith size remains F-20/F-44.]

### F-43 — P2 · ARM differential-vector gap, quantified

**Evidence:** the x86 side has `library/x86ins.sov` (5,004 lines, vectors "taken from a real processor" per its header) plus the emulator permission boards; the ARM side has no vector suite at all — its emulator (`library/arm.sov`, 34 KB) is exercised only by compile checks and the four unreferenced helpers (F-39). The second emulator is therefore far less differentially tested than the first. [Roadmap Phase 5 "differential absent for ARM"; Chen et al. CSUR 2020 on differential testing as the compiler-testing workhorse.]

**Suggested fix:** port the x86 vector harness shape to ARM (in-Sovren; the `arm_why`/`arm_result` helpers already exist for the job). **Wave 3.**

### F-44 — P2 · Size concentration and the suite decomposition proposal

**Evidence:** largest files — `cx86.sov` 315 KB, `x86.sov` 304 KB, `suite.sov` 178 KB, `carm.sov` 121 KB (of ~49k library LOC total). The suite's 39 check groups (§2) map 1:1 to files, so decomposition is mechanical: one file per board (`tr_perm_checks` → `suite-perm.sov`, …) with a thin `suite.sov` that `use`s them and calls them in order. This preserves the roadmap's constraints: no build step is introduced (I1), and the "one list of checks" property survives as the ordering file. [H15/F-20.]

**Suggested fix:** split when the suite next grows past a maintainable size; the probe family naming already anticipates it. **Wave 3.**

### F-45 — Info+ · Back-end hook contract is consistent

All three x86 compilers expose the same five core-facing tasks — `try_sbss`, `spawn_arg`, `emit_write_lit`, `compile`, `poke2` (`compilers/{linux,windows,macos}/compiler.sov`, verified by task-header extraction) — with target-specific tasks layered on top (windows adds the import-table family `imp_name/imp_pos/imp_mark/win_head_byte/win_nib`; linux adds the ELF writers `write_elf/fmt_file/run_prog`). The shared-core/target-layer split is structurally clean, complementing F-34 (zero task-name collisions with `cx86`).

### F-47 — P2 · Coverage proxy and mutation gate (proposal; pilot already executed)

**Coverage proxy (feasible, in-Sovren):** the emulator decodes every guest instruction already — recording the guest PC into a bitmap inside `x86_run` (one poke per basic block) yields per-check guest coverage; on the compiler side, the probe files are already named by pass family (`ci/cs/dp/gd/…`), so a pass-hit counter per probe run gives pass-level coverage. Both are pure additions to `testrun.sov`/`x86.sov` (I8).

**Mutation gate (pilot result F-35):** 2/2 mutants survived the 551-check battery. Proposal: a nightly job that mutates `.sov` text (operator/constant/shape flips), rebuilds the compiler with the seed, runs the battery, and reports kill-rate — the infrastructure already exists (bootstrap + suite). Target threshold: 100% kill on the compiler core and crypto board before merging to main. [AugmentCode mutation-testing guidance; roadmap §8 Step 5's test-first rule.]

---

## 2. Phase 5 deliverable — test-asset inventory and oracle classification

**Inventory.** 39 top-level check groups in `library/suite.sov` (the battery's 551 checks live inside them), 110 probe files under `tests/`, two tiers (`all.sov` full, `fast.sov` 14-skip), plus the fuzzer, race detector, debugger, and the two emulators. The 39 groups:

`tr_perm_checks · tr_pie_win_checks · tr_win_thread_checks · tr_pie_mac_checks · tr_pie_android_checks · tr_pie_ios_checks · tr_emu_pe_refuses · tr_emu_macho_refuses · tr_emu_arm_refuses · tr_canary_droid_checks · tr_canary_ios_checks · tr_xnu_table_checks · tr_launcher_byte_checks · tr_seed_byte_check · tr_debug_map_check · tr_debug_code_check · tr_debug_trace_check · tr_lz_checks · tr_repl_checks · tr_browser_checks · tr_os_checks · tr_lz2_checks · tr_ret_checks · tr_szv_checks · tr_safe_checks · tr_termkit_checks · tr_crash_droid_checks · tr_crash_ios_checks · tr_s56_win_checks · tr_crash_mac_checks · tr_canary_mac_checks · tr_canary_checks · tr_crash_checks · tr_pie_checks · tr_pe_checks · tr_thread_checks · tr_privacy_checks · tr_strict_checks · tr_every_lib_checks`

**Oracle classification** (by group name and content):

| Oracle class | Groups | Strength |
|---|---|---|
| Byte-identity / fixed point | `tr_launcher_byte_checks`, `tr_seed_byte_check` | strongest (reproducibility anchor) |
| Format-spec known-answer (PE/ELF/Mach-O) | `tr_pie_*`, `tr_pe_checks`, `tr_xnu_table_checks` | strong (spec-derived) |
| Differential / emulator-vs-hardware | `tr_emu_*_refuses`, permission boards inside `tr_perm_checks` | strong where vectors exist (x86); weak on ARM (F-43) |
| Crypto known-answer (RFC/NIST vectors) | crypto boards inside `tr_safe_checks` and the crypto groups | strong (external vectors) |
| Fault-injection property | `tr_canary_*`, `tr_crash_*` | medium-strong (property, not vector) |
| Behavioral compile-run-compare | `tr_repl_checks`, `tr_browser_checks`, `tr_os_checks`, `tr_lz_checks`, `tr_lz2_checks`, `tr_termkit_checks`, `tr_ret_checks`, `tr_szv_checks`, `tr_strict_checks` | medium (self-authored expectations) |
| Capability scan (binary-level) | `tr_privacy_checks` | strong (independent of the compiler's own output logic; re-derived in F-26) |
| Build-only | `tr_every_lib_checks` | weak (compilation ≠ behavior — F-32/F-38) |

**Self-referential-oracle review (H9):** the compile-run-compare model is self-referential by construction, but every expected value in the battery is a hand-written literal, not compiler output. The residual meta-circularity risk is precise: a seed-compiler bug that miscompiles the suite itself could hide bugs — mitigated in-tree by (a) the bootstrap fixed point (the built compiler is byte-identical to the seed, so "the compiler under test" is anchored to one fixed binary), (b) hardware-derived x86 vectors, and (c) the emulator permission boards, which catch wrong codegen independently of source-level expectations. Residual risk: **low but nonzero**; the mutation pilot (F-35) is the honest ongoing measurement of it.

**Pyramid shape:** the battery is effectively all integration-tier (write → compile → run → compare). The unit tier exists as libraries (`assert.sov`, `test.sov`) but is unused (F-40). Per the roadmap's purpose guard (I8), importing a foreign pyramid is wrong for this project; the sanctioned shape is "the battery is the integration tier, and per-library behavioral checks are the unit tier" — which is exactly what F-32/F-38 propose extending.

**Defect-escape review:** the suite's own header (`suite.sov:12-14`) documents that the permission boards "found real bugs, twice" — regression checks exist where real bugs were found. The gap: no boards yet for the classes this audit found (TLS crypto, compiler-core codegen) — the Resolution Plan's Step 5 rule (no fix lands without a failing check) closes this going forward.

**Not completed this session (parked):** REPL per-line latency measurement (Phase 3), register-allocation quality review (Phase 3), allocator time-to-OOM at the 64 MB ceiling (Phase 3), mechanical all-168-library sweep of the `mem.sov` universal-builtin rule (Phase 4). These remain unchecked in the roadmap.

---

## 3. Hypotheses register — deltas from this session

- **H7** (per-target divergence despite shared cores) → **refuted at the core level**: all x86 back ends `use cx86` with zero task collisions (F-34), the hook contract is identical (F-45), and the bootstrap fixed point proves the committed binaries match the sources byte-for-byte. Target layers differ *by design*.
- **H9** (meta-circularity) → mitigation stack verified; residual risk stated low-but-nonzero (§2).
- **H10** (isolation hazards) → confirmed earlier (F-11); the fix mechanism (`time_ms`-suffixed fixtures) is validated as cross-target because the suite already depends on `time.sov` on all three OS runners.
- **H11** (no coverage/mutation/benchmark gates) → **confirmed empirically** (F-35: 2/2 mutant survivors).
- **H14** (global-state coupling) → **largely refuted at the feared scale** (F-41: 10 shared globals in the core, purposeful).
- **H15** (suite monolith + skip-list governance) → split verdict: governance sound (F-42), size concentration real (F-44).

## 4. References

**Repository evidence (primary):** `library/sha1.sov:1`; `.github/workflows/check.yml:18, 273, 314, 335`; `.github/workflows/legacy.yml:14`; `library/suite.sov:12-14` and the 39 `tr_*_check` definitions; `tests/fast.sov:1-39`; `library/x86.sov` (`x_w_pminuw`, `x_w_pminud`, `x_w_pabsw`, `x_w_vpermilps`, `x_w_vpermilpd`, `x_vminmax`, `x86_used_syscall`); `library/arm.sov` (`arm_why`, `arm_low`, `arm_result`, `arm_run_symbol`); `library/cx86.sov` (branch globals `bk/bi/bj/bs/be`); `compilers/{linux,windows,macos}/compiler.sov` (hook tasks `try_sbss/spawn_arg/emit_write_lit/compile/poke2`; `fn_names/fn_offs`); `library/assert.sov`, `library/test.sov`, `library/testrun.sov`, `library/time.sov`; `library/x86ins.sov` header.

**External standards (secondary):** SLSA Build Track L3 (pinned dependencies) — https://slsa.dev/spec/v1.0/build; OpenSSF Scorecard, "Pinned-Dependencies" — https://github.com/ossf/scorecard; Chen et al., *A Survey of Compiler Testing* (CSUR 2020) — https://www.software-lab.org/publications/csur2019_compiler_testing.pdf; AugmentCode, *Mutation Testing* (kill-rate methodology); Google Testing Blog, flaky-test ceilings (≤1%); roadmap Appendix D items 1–19.

---

*Phases 4 and 5 are complete (parked items listed in §2). Phases 6 (DX/docs/CI), 7 (synthesis), and 8 (Resolution Plan) remain. The repository was not modified at any point in this session.*
