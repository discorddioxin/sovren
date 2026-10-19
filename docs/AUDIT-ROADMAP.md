# Sovren — Audit Session Roadmap & Charter

| | |
|---|---|
| **Repository** | `discorddioxin/sovren` (branch `arena/b631e036-sovren`, base commit `003149e` "Placeholder") |
| **Document version** | 1.1 — 2026-10-18 (amended per `docs/PROGRAM-ANALYSIS.md`: purpose-protecting invariants added) |
| **Status** | COMPLETE — Phases 0–8 executed plus a verification addendum (CT inventory closed, P0/P1 re-derived, parked items resolved); deliverables in `docs/audit/` (start here: `FINDINGS-SUMMARY.md`; then the four findings logs, `audit-report.md`, `resolution-plan.md`, `findings-verification-addendum.md`). Repo source never modified. |
| **Ground rule** | **Read-only.** This session makes no code changes. Every proposed change is written down as a *suggestion* in the audit outputs (findings register → Resolution Plan). Analysis scripts, if any, run from `/tmp`; all build/test artifacts go to `/tmp`; `git status` must be clean at the end of every session day. |
| **License note** | The PSVL v1.0 license explicitly permits this work: the source is published "to allow evaluation, security auditing, performance research, learning the language, and official…" use. The audit operates inside that grant. |

---

## 1. Purpose and non-goals

**Purpose.** Run a phased, evidence-based audit of the entire Sovren repository — bugs, performance, code architecture, and testing strategy — and end the session with a **Resolution Plan**: a prioritized, consecutive-steps roadmap for fixing what the audit finds.

**In scope**

- All source: `bootstrap.sov`, `launcher.sov`, `repl.sov`, `runtime.sov`, `compilers/*/compiler*.sov`, `library/*.sov` (168 files), `tests/**` (136 files), `tools/debug.sov`, `.github/workflows/*`, committed binaries, LICENSE.
- The compiler pipeline (lexer → passes → codegen) for all six targets: Linux ELF x86-64, Windows PE32+, macOS Mach-O x86-64, Android aarch64 ELF, iOS arm64 Mach-O, bare metal (+ `--android-so`).
- The runtime (bump allocator, syscall layer), the in-language emulators (`x86.sov`, `arm.sov`, `cx86.sov`, `carm.sov`), the standard library (including hand-rolled crypto and TLS), and the test infrastructure itself.

**Non-goals**

- No code edits, no commits, no branch creation beyond the session branch, no dependency changes.
- No penetration testing of external services (Telegram/Discord libraries are audited statically; the CI-style local mock server pattern is the reference for any dynamic check).
- No formal verification pass (out of budget; flagged as a strategic recommendation if warranted).

---

## 2. Repository profile (from pre-research — the facts the audit builds on)

| Dimension | Finding from pre-research |
|---|---|
| Project type | Self-hosting systems language + native compiler, written entirely in itself; no interpreter |
| Size | 328 tracked files, 5.6 MB, ~73,200 lines of `.sov`; single commit ("Placeholder") — **no history to mine** |
| Bootstrap | 10,000-byte ELF seed `sovren` + 12,008-byte `sovren.exe`; `bootstrap.sov` rebuilds all ten artifacts and byte-compares; seed fixed point g3==g4==g5 |
| Compilers | Per-target: linux 2,634 / windows 3,789 / macos 2,836 / ios 1,027 / android 888 / android-so 1,466 lines; shared cores `cx86.sov` (323 KB, x86 backends) and `carm.sov` (124 KB, arm64 backends) claim verbatim byte-identity |
| Passes | 140+ numbered compiler passes observed (up to "pass 142"), incl. relaxation (69), permission model (S8), frame wipes (117/118) |
| Runtime | `runtime.sov` (690 lines): 64 MB mmap heap, **bump allocator that never frees**, atomic spinlock for alloc, `syscall` is the only builtin |
| Memory model | **All indexing unchecked by default**; `library/bounds.sov` provides opt-in checked indexing (on by default, `bounds_off()` to disable) |
| Crypto | Hand-rolled: AES, GCM, ChaCha20-Poly1305, Poly1305, SHA-1, SHA-256, HMAC, HKDF, PBKDF2, X25519, bigint, fixed-point; TLS 1.2 client (`tls.sov`, header admits *"Batteries, not certified: review before production crypto"*); `vault.sov` AES-256-GCM + PBKDF2 |
| RNG | `rand.sov`: kernel `getrandom` for bytes, but `rand_below n = rand_u8() % n` (**modulo bias**, 256-value ceiling) |
| Emulators | x86-64 and AArch64 CPUs written in Sovren; used to run PE/Mach-O guests, run the Windows compiler itself, and differentially test instruction semantics (`x86ins.sov`, 5,004 lines, vectors "taken from a real processor") |
| Tests | Battery in `library/suite.sov` (182 KB) driven by `testrun.sov`; two tiers (`all.sov`, `fast.sov` with a documented 14-item skip list, ~105 s full); 110 probe files (`ci/cs/dp/gd/gl/pa/pd/ph/pk/ps/pt/rot/rr/sa/sel/sq/tw/xe/div/r11`); fuzzer `fuzzlib.sov`+`fuzz_run.sov` (LCG PRNG, fixed seeds, 300 programs, arithmetic/if/loop grammar only); static race detector `race.sov` |
| CI | `check.yml` on every push/PR on **real** Windows/macOS/Linux runners; `legacy.yml` weekly cron for `tests/run.sov`; includes PE header/reloc validation, self-host byte-identity, every-library-on-every-target, zero-warnings gate |
| Docs/metadata | **No README, no docs directory, no CONTRIBUTING, no issue templates, no package manifest**; guidance lives in unusually good source comments |
| License | PSVL v1.0, proprietary source-visible, © 2026 Elxan Hüseynov |

---

## 3. Research basis (why the phases are shaped this way)

Decisions in this roadmap follow published methodology, not ad-hoc taste:

1. **Audit process** — scope → freeze baseline → automated scanning before manual review → high-risk manual review → findings register with severity → remediation tracking (OWASP Secure Code Review Cheat Sheet; Wiz/SentinelOne/ForaSoft audit-process guides; Sonarsource review lifecycle).
2. **Compiler testing** — the test-oracle problem is solved empirically by **differential testing** (McKeeman; Csmith), **metamorphic/EMI testing**, and **translation validation**; miscompilation impact must be measured on real programs, not just crash counts (Yang et al. PLDI'11; OOPSLA'19 "Compiler Fuzzing: How Much Does It Matter?"; CSUR 2020 survey of compiler testing; arXiv:2306.06884).
3. **Crypto review** — constant-time discipline (no secret-dependent branches, memory addresses, or variable-latency operands), verified **at the binary level** because compilers can break source-level CT guarantees ("Breaking Bad", arXiv:2410.13489; Intel side-channel guidance; HACL* secret-independence practice; ct-verif/dudect lineage).
4. **Testing-strategy audit** — pyramid shape, branch > line coverage, **mutation score** as the honest oracle-quality metric, flaky-test quarantine with ≤1% ceiling (Google published ~1.5% flaky rate), tiered CI gates with time budgets, defect-escape-rate as the north-star metric.
5. **Specification-first checking** — for multi-implementation systems (six backends, two emulators), turn normative requirements into checklists before diffing implementations, because differential signals are blind when all implementations share the same wrong reading (SPECA, arXiv:2602.07513).
6. **Trust** — a self-hosting compiler's TCB includes the seed binary; reproducibility proofs (byte-identical rebuilds) mitigate build-time tampering but not seed bugs (Thompson's "Reflections on Trusting Trust" lineage).

---

## 4. Audit principles

- **Evidence first.** Every finding carries `file:line` references plus either a reproducer (a `.sov` program + observed vs. expected) or a precise reasoning chain. No evidence → no finding.
- **Adversarial validation.** The verifier of a finding is never its finder; every P0/P1 is independently re-derived before it enters the Resolution Plan.
- **Severity = impact × likelihood**, never checklist deviation counts. A deviation with no reachable path is Minor at most.
- **Reproducibility.** Every dynamic check runs from a frozen commit hash, recorded in the findings register.
- **No code changes.** Suggestions are written as proposals with acceptance criteria; the repo stays pristine.
- **Meta-circularity guard.** Tests are written in the language under test, so test-suite results are only as trustworthy as the compiler. Every suite-level "pass" that matters is cross-checked against at least one independent oracle (hardware-derived vectors, RFC test vectors, the second emulator, or a native cross-compiled binary).

### 4.1 Purpose-protecting invariants (do-not-harm constraints)

Sovren's purpose — *a complete, dependency-free, self-hosting native toolchain, honest about its limits, private by default, fast by default* — is carried by deliberate, source-documented decisions. The audit must audit **with** the design, not against it. These invariants (full evidence in `PROGRAM-ANALYSIS.md` §3) constrain every finding and every suggested fix:

| # | Invariant | Consequence for the audit |
|---|---|---|
| **I1** | Self-containment: `syscall` is the only builtin; no external build/run dependencies | Suggested fixes must be implementable **in Sovren**; "replace with library X" is not a valid fix |
| **I2** | Self-hosting with byte-identity proofs (seed → fixed point) | The seed binary is the axiom; verify its *behavior* (e.g., under the in-language emulator), never propose regenerating it from absent C source |
| **I3** | One source, six targets; shared cores byte-identical; shared libraries use only universal builtins (`mem.sov` rule) | Divergence findings must preserve the shared-core model |
| **I4** | Speed by default: unchecked indexing, no GC, no runtime checks in the default path; safety opt-in (`bounds.sov`, arenas) | Never file unchecked-by-default as a bug; never recommend GC or default-path checks |
| **I5** | Honesty: strict emulation, plain errors, no silent fallbacks, limits documented | Gaps between *stated* behavior and actual behavior are bugs; stated limits are not |
| **I6** | Privacy/capability discipline: capability-free compiler source, no build metadata, bit-identical rebuilds (suite pass 115) | Verify the invariant; no recommendation may add capabilities (no telemetry, no phone-home) |
| **I7** | Determinism: fixed fuzz seeds, reproducible builds, opt-in timing | Fuzzing recommendations keep the fixed seed as the regression default |
| **I8** | Dogfooding: tests, debugger, race detector, fuzzer, emulators are all Sovren programs | Tooling recommendations extend in-Sovren tools (`fuzzlib.sov`, `testrun.sov`), not external frameworks |

**Standing rule.** A finding against a deliberate, documented decision is a **design proposal**, not a bug, and requires a design-decision record before it enters the Resolution Plan. The confirmed first instance of the drift class: `runtime.sov`'s spawn comment ("a spawned job must not allocate from the heap yet") is stale — `_sov_alloc` carries an atomic spinlock. File as comment drift, not a race.

---

## 5. Session logistics

**Team (roles, not headcount):** Audit lead (scope, triage) · Compiler/language reviewer · Security & crypto reviewer · Testing/DX reviewer · rotating **adversarial verifier** (never verifies own findings).

**Cadence (10 working days):**

| Day | Phase |
|---|---|
| 1 (AM) | Phase 0 — baseline & freeze |
| 1 (PM)–2 | Phase 1 — correctness & defect hunt |
| 3–4 | Phase 2 — security audit |
| 5 | Phase 3 — performance audit |
| 6–7 | Phase 4 — architecture & code quality |
| 7–8 | Phase 5 — testing strategy audit |
| 8 (PM) | Phase 6 — DX, docs, CI/CD & release |
| 9 | Phase 7 — synthesis, verification, scoring |
| 10 (AM) | Phase 8 — Resolution Plan drafting |
| 10 (PM) | Readout, sign-off |

**Artifacts produced (all in `docs/audit/`, none of them code):** `findings-register.md` (Appendix B schema), one `phase-N-report.md` per phase, `audit-report.md` (final), `resolution-plan.md` (Phase 8 output), `baseline-metrics.md` (Phase 0 output).

**Daily ritual (15 min):** new findings triaged into the register; duplicates merged; tomorrow's checklist adjusted.

---

## 6. Phase plan

**Session progress (2026-10-18):** Phase 0 ✅ · Phase 1 ✅ (F-01…F-20) · Phase 2 ✅ (F-21…F-27) · Phase 3 ✅ (F-28…F-31) · Phase 4 ✅ (F-32…F-35, F-38…F-45) · Phase 5 ✅ (F-35, F-46, F-47) · Phase 6 ✅ (F-48…F-55) · Phase 7 ✅ (`audit-report.md`) · Phase 8 ✅ (`resolution-plan.md`). Checkboxes below are ticked only where the activity's evidence exists in a findings document; four partially-done items are annotated and left unticked.


### Phase 0 — Preparation, baseline, freeze (Day 1 AM)

**Objective.** Make every later finding reproducible and every later comparison quantitative.

**Activities**
- [x] Record freeze commit hash, toolchain versions, host OS/arch for each runner class (Linux/Windows/macOS).
- [x] Reproduce the bootstrap: run `./sovren bootstrap.sov`; confirm "bootstrap clean" (ten artifacts byte-identical + seed fixed point). Record wall times.
- [x] Run `tests/all.sov` end-to-end; capture pass/fail/skip counts and the ~105 s baseline; run `tests/fast.sov` for the edit-loop baseline.
- [x] Capture metric baselines: compile time of `tests/hello.sov` per target; binary size per target; emulator steps/sec (documented ~2.5M/s on the self-build workload); suite duration per check via `tr_time: 1` (the suite already ranks its slowest checks — harvest that list).
- [x] Build the component map and attack-surface map (entry points: CLI args, `use` resolution, file I/O, sockets, TLS, X11, stdin/keyboard, spawn/join, shared globals).
- [x] Risk-rank components by (blast radius × exposure × change frequency) to weight manual review effort — crypto, TLS, allocator, codegen passes, and the seed binary get senior time first.

**Deliverable.** `baseline-metrics.md` + frozen environment manifest.
**Exit criteria.** Bootstrap reproduces byte-for-byte on at least one machine; full suite green; baselines tabulated.
**Timebox.** 2 hours.

---

### Phase 1 — Correctness & defect hunt (Days 1 PM–2)

**Objective.** Find bugs: wrong output, crashes, hangs, undefined behavior, error-path failures — in the compiler, runtime, libraries, and tools.

**Key activities**
- [x] **Error-path sweep.** Every `syscall`/`tr_*`/file/network call site: is the failure return checked, and is the failure *message* actionable? (The codebase already uses `str_has(msg, "Error")` probing — audit its completeness and precision.)
- [x] **Unchecked-indexing audit.** Default-unchecked `peek/poke` + opt-in `bounds.sov`: enumerate libraries that index user-influenced data without bounds checks (parsers: JSON, CSV, INI, TOML, DER walker, BMP, escape).
- [x] **Arithmetic edge cases.** bigint/fixed-point overflow, division by zero (`div` probes exist — check coverage of remainder sign, INT_MIN-class cases), negative shifts, 32/64-bit width assumptions (`bit32` vs `bit64`).
- [x] **Parser/lexer edge cases.** Empty files, unclosed quotes/brackets, deep nesting (stack depth in the recursive-descent JSON reader), unicode/UTF-8 in strings and identifiers, CRLF, `\0` in strings, extremely long identifiers/lines.
- [x] **Concurrency.** `spawn`/`join` semantics; the atomic alloc lock; `race.sov` is deliberately conservative — characterize its false-negative classes (tasks whose bodies avoid the words lock/mutex/atomic; non-global shared state; heap aliasing).
- [x] **Per-target divergence.** Same program compiled for all six targets must behave identically where the ABI allows; probe any target-only code paths (`bare_mode`, `run_mode`, `fmt_mode`, `dbg_mode`).
- [x] **REPL/debugger.** `repl.sov` per-line compilation model: state leakage between lines, `use` carry-over; `sovren-dbg` line attribution (call windows outside recorded ranges).
- [x] **Launcher/bootstrap.** `launcher.sov` edge cases: missing seed, unwritable output, target flag conflicts.

**Methods.** Manual review of hot paths; differential execution (compile-run-compare across all targets); the existing probe suite as a coverage map (which passes have probes, which don't); small hand-written `.sov` reproducers run in `/tmp` (never committed).

**Purpose guard (I4/I5).** Unchecked indexing, the never-freeing bump allocator, and the REPL's compile-per-line cost are *documented design decisions*, not defects — file them only as design proposals with evidence of accidental harm. Comment/code drift (see §4.1) is its own finding class.

**Deliverable.** `phase-1-report.md` + findings register entries.
**Exit criteria.** Every check in Appendix A.1 attempted; each finding has evidence + severity.
**Timebox.** 1.5 days.

---

### Phase 2 — Security audit (Days 3–4)

**Objective.** Find exploitable weaknesses and quantify the trust boundary picture.

**Key activities**
- [x] **Threat model (STRIDE).** Map trust boundaries: compiler input (`.sov` text) → generated binary; runtime ↔ kernel (syscalls); TLS client ↔ network; bot libraries ↔ platform APIs; emulator ↔ guest binaries.
- [x] **Crypto review** (highest senior density): AES/GCM/ChaCha20-Poly1305/Poly1305/SHA-256/X25519/bigint — constant-time discipline at **source and emitted-binary level** (secret-dependent branches, table lookups on secrets, variable-latency ops); RNG quality (hypothesis H2: modulo bias in `rand_below`, 256-value ceiling); nonce/key handling and wipe coverage; PBKDF2 iteration floors. SHA-1: file as *"deprecated primitive reachable by default"* with a documentation/warning fix — it is present for learning and compat, and removal is a design decision (I1/I5), not a bug fix.
- [x] **Privacy-invariant verification (I6)**: re-derive the pass-115 checks independently — no network-syscall encodings in plain output/compiler/launcher, no build-machine metadata, bit-identical rebuilds, and **capability-free compiler source** (no network/process/clock syscalls). Confirm no audit recommendation could add a capability.
- [x] **TLS client (`tls.sov`)**: certificate validation completeness in the DER walker (expiry, hostname, chain, key usage, signature verification), downgrade resistance, record fragmentation, PRF correctness against RFC 5246 vectors.
- [x] **`vault.sov`**: confirm the AAD gap its own comment admits (header not covered by the GCM tag → `iters` work-factor tampering) and any key-derivation edge cases.
- [x] **Memory safety**: unchecked indexing (H3), allocator behavior at the 64 MB ceiling (mmap failure path), heap growth past `heap_end`, secret residue in the never-freed heap (documented in `secret.sov` — verify the mitigations: `wipe`, `private` frames, `PR_SET_DUMPABLE`).
- [x] **Hardening validation**: NX (PT_GNU_STACK RW), Windows PIE + `.reloc` (CI already asserts PE flags — re-derive independently), canary/wipe-at-exit behavior, "no raw Linux syscalls in the PE" invariant.
- [x] **Supply chain**: seed binary provenance (H1: the 10 KB seed is the axiom of the TCB — recommend provenance documentation and emulator-based behavioral verification, *not* regeneration, since no seed source exists in-repo, I2); committed artifact freshness (bootstrap proves it); workflow pinning (`actions/checkout@v4` is tag-pinned, not SHA-pinned); runner trust (real-hardware runners are strong but queue-owned).
- [x] **Secrets scan** (gitleaks-class sweep over history and working tree — trivial here: one commit, but do it).
- [x] **License/legal**: PSVL obligations, attribution requirements, compatibility of the source-visible grant with the audit's own outputs. The proprietary source-visible license is deliberate — do not recommend relicensing, and do not recommend a package manager or registry publication (violates I1).

**Methods.** Manual crypto review against the constant-time literature; source-level taint walk from external inputs to dangerous sinks; binary-level spot checks of emitted crypto code paths via the in-language x86 emulator (step-trace timing variance as a cheap dudect-style probe); RFC test vectors for TLS/PRF/HKDF/PBKDF2.

**Deliverable.** `phase-2-report.md` + findings (CVSS v4 scores for exploitable items).
**Exit criteria.** Every Appendix A.2 item attempted; crypto paths have a CT-classification inventory (constant-time vs variable-time, with `file:line` evidence).
**Timebox.** 2 days.

---

### Phase 3 — Performance audit (Day 5)

**Objective.** Quantify speed, memory, and size; find algorithmic and codegen waste.

**Key activities**
- [x] **Compiler throughput**: time-to-binary across the six targets and across file sizes (10 / 1k / 10k lines); identify super-linear passes (string rebuilds, patch-list rescans, relaxation pass 69, branch registration).
- [ ] **Codegen quality**: register allocation effectiveness, missed immediates, redundant moves/loads, dead-code elimination, prologue/epilogue bloat; compare against hand-expected encodings for the probe-traced ops.
- [ ] **Runtime**: bump-allocator behavior under long-running tasks (no free → 64 MB ceiling; measure time-to-OOM on an allocation-heavy guest); `str_cat`/concat-in-loop costs; atomic lock contention under `spawn`. *partial: ceiling behavior measured — the ceiling is unenforced, 200 MB writable (F-57); concat-in-loop measured (F-30); lock contention deferred*
- [x] **Emulator speed**: steps/sec baseline (2.5M/s documented) and per-instruction cost distribution; identify the hottest decode paths.
- [x] **Binary size**: per-target hello-world sizes; section layout (.text/.rdata/.reloc); map-file overhead in `--debug` builds.
- [x] **Benchmark hygiene**: `tests/bench.sov` and `library/bench.sov` — are the benchmarks committed, deterministic, and gated? Propose a benchmark gate if absent.
- [x] **REPL latency**: the documented 1–2 s/line compile cost — measure and bound. *measured: 5 ms/line (F-51); the header claim is ~200× stale*

**Methods.** Wall-clock timing with repetition (hyperfine-style, run from `/tmp`); emulator instruction-frequency traces as a profiler; asymptotic review of pass data structures (lists vs maps for lookups); A/B compile of identical programs across targets.

**Purpose guard (I4).** Every optimization candidate must preserve the zero-cost default path: no GC (arenas are the sanctioned remedy for allocation growth), no default-path bounds checks, no runtime bloat. The REPL's compile-per-line latency is documented honesty (I5) — measure and bound it, do not redesign it.

**Deliverable.** `phase-3-report.md` + `baseline-metrics.md` performance section + ranked optimization candidates (expected win × effort).
**Exit criteria.** Every Appendix A.3 item attempted; top-5 hot paths identified with data.
**Timebox.** 1 day.

---

### Phase 4 — Architecture & code quality (Days 6–7)

**Objective.** Assess the design: module boundaries, coupling, duplication, evolvability, and the language itself.

**Key activities**
- [x] **Dedup integrity**: `cx86.sov`/`carm.sov` are claimed "pulled verbatim" from the per-target compilers — verify mechanically (extract and diff the shared regions); audit the non-shared parts (image writers, syscall tables, entry conventions) for drift risk (H7).
- [x] **Architecture-rule verification (I3)**: confirm the `mem.sov` rule — *a shared library may only use a builtin that every target has* — holds across all 168 libraries; confirm the `cx86.sov` naming rule (*"a shorter name must never win over a longer"*) in the resolver.
- [x] **Global mutable state**: the compiler communicates via globals (`oc`, `err_line`, `patch_at`, …); `carm`/`cx86` depend on compiler-defined globals. Map the dependency graph; **assess and document** the cost (re-entrancy, testability, future parallel passes) — the single-pass, no-types design makes globals intrinsic; restructuring is a design proposal, not a defect (I4/I5).
- [x] **File-size and function-size distribution**: `suite.sov` 182 KB, `cx86.sov` 323 KB, `x86.sov` 312 KB, `carm.sov` 124 KB — assess decomposition boundaries. Any decomposition must preserve the *"one list of checks"* property and the no-build-system model (splitting via additional `use` files is allowed; introducing a build step is not, I1).
- [x] **`use`-graph analysis**: cycles, layering violations (library → compiler internals), orphan files (never `use`d), missing `use` declarations.
- [x] **Error model**: string-probing (`str_has(msg, "Error")`) vs structured errors; consistency of the `0`-return convention; error message quality (do they name the file/line?). The text-based error model is deliberate in a typeless language — file structured errors as a design proposal only.
- [x] **Language design review**: no types (documented), dynamic values as text; assess implications for the compiler's passes and for users; undocumented semantics discovered during Phases 1–3 get logged as spec gaps.
- [x] **Naming, comments, consistency**: the comment culture is a stated asset — check whether it is uniformly true (stale comments are worse than none).
- [x] **Dead code / duplicated logic** sweeps across the six compilers and 168 libraries.

**Methods.** Static graph analysis (build the `use` map with grep/scripting from `/tmp`); manual design review of the pass pipeline; comment-truth spot checks on the riskiest files.

**Deliverable.** `phase-4-report.md` + architecture diagrams (data flow, pass pipeline, module graph) + findings.
**Exit criteria.** Every Appendix A.4 item attempted; component coupling map published.
**Timebox.** 2 days.

---

### Phase 5 — Testing strategy audit (Days 7–8)

**Objective.** Audit the tests themselves: do they prove the right things, with honest oracles, at the right speed?

**Key activities**
- [x] **Inventory & taxonomy**: classify all 136 test assets (compile-run-compare, compile-fail, byte-identity, differential-hardware, cross-emulator, permission-fault, PE-header validation, drawing-pixel, mock-server, self-host fixed point).
- [x] **Oracle quality**: where does each expected value come from — real-hardware differential vectors (strong), RFC vectors (strong), hand computation (medium), or self-reference (weak)? Flag self-referential oracles.
- [x] **Pyramid shape**: the suite is effectively all integration-level (compile+run+compare). Assess the absence of a unit layer and whether the language affords one; check the two-tier split (`all` vs `fast` skip list) for governance: is the skip list reviewed, are the 14 skips still justified?
- [x] **Fuzzing maturity** (H8): LCG PRNG, fixed seeds, 300 programs, grammar limited to expressions/if/loop. Assess against coverage-guided, grammar-aware, corpus-persisting, minimizing fuzzers; note the oracle design (self-evaluator) and its blind spots.
- [x] **Differential & metamorphic testing**: present for x86 instruction semantics and the self-host fixed point; absent for ARM (beyond `arm64/verify`), for optimization levels, and as EMI/metamorphic families. Quantify the gap.
- [x] **Coverage**: no coverage measurement exists. Propose a feasible proxy: emulator step-trace coverage of compiled guests, and pass-level coverage of the compiler (which passes each probe exercises).
- [x] **Mutation testing**: none exists. Propose a pilot: mutate compiler source (operator flips, pass reordering) and measure suite kill-rate — the honest test-quality metric.
- [x] **Isolation & determinism** (H10): hardcoded `/tmp` paths (`/tmp/sov-perm.bin`, `/tmp/repl_run.bin`, `/tmp/hello-emu.exe`, …) collide under parallel CI; `sleep`-based synchronization around Xvfb and the mock HTTP server; `time_ms`/`getrandom` nondeterminism in checks.
- [x] **CI gating**: `check.yml` gates every push (strong); assess runner-OS matrix completeness (no bare-metal target run; android/ios compile-only), failure signal quality (does a failure name the check?), retry policy, and the weekly `legacy.yml` rot-prevention job.
- [x] **Meta-circularity** (H9): tests are Sovren programs compiled by the compiler under test. Verify the mitigation stack (hardware-derived vectors, emulator cross-checks, byte-identity fixed point) and define its residual risk.
- [x] **Defect-escape review**: for each historical bug class the comments mention ("found real bugs, twice"), confirm a regression check exists and would fire.

**Methods.** Test inventory scripting from `/tmp`; oracle-classification table; flakiness hunt (repeat runs, timing-sensitive checks); mutant pilot on a small pass; CI YAML review against the tiered-gate pattern (smoke < 5 min on PR, full nightly).

**Purpose guard (I7/I8).** All tooling recommendations must be **in-Sovren**: extend `fuzzlib.sov` (corpus persistence, mutation operators, optional per-run seed — the fixed seed stays the regression default for reproducibility), use the emulator's step trace as coverage feedback, and mutate `.sov` text for mutation testing. External frameworks (libFuzzer, gcov, pytest-style runners) cannot apply to a self-contained toolchain and must not be recommended. The existing unit layer (`assert.sov`, `test.sov`) and the compile-run-compare model *are* the unit tier — do not import a foreign pyramid shape. Keep the real-hardware CI philosophy; recommend isolation (`mktemp`) and deterministic sync, which strengthen I7.

**Deliverable.** `phase-5-report.md` + test-strategy scorecard (pyramid, oracles, isolation, gating, metrics) + maturity assessment vs. the testing-maturity model.
**Exit criteria.** Every Appendix A.5 item attempted; every test asset classified; top-5 testing gaps ranked.
**Timebox.** 2 days.

---

### Phase 6 — DX, documentation, CI/CD & release (Day 8 PM)

**Objective.** Audit the human surface: can a newcomer learn, build, and trust this?

**Key activities**
- [x] **Onboarding**: no README (H12) — measure time-to-first-compile for a stranger using only the repo; the CLI help text is good; what's missing (language reference, tutorial, semantics of `use`, error catalog)?
- [x] **Documentation truthfulness**: source comments are the docs — sample-audit their accuracy against behavior.
- [x] **Release engineering**: committed binaries + bootstrap proof; versioning (`Sovren 0.1.0` string); changelog absence; artifact naming (`compiler-so` vs `compiler`).
- [x] **CI health**: real-hardware runners (strength) vs queue dependence (risk); no caching; no runner-image pinning; workflow YAML lint; weekly legacy job value.
- [x] **Issue/process hygiene**: no issue templates, no CONTRIBUTING, no SECURITY policy, single-commit history (H16: no archaeology, no blame path).
- [x] **Accessibility of the audit itself**: can a future auditor reproduce this session from these docs?

**Deliverable.** `phase-6-report.md` + findings.
**Exit criteria.** Every Appendix A.6 item attempted.
**Timebox.** 0.5 day.

---

### Phase 7 — Synthesis, verification & scoring (Day 9)

**Objective.** Turn raw findings into a verified, prioritized, non-duplicated body of evidence.

**Activities**
- [x] Deduplicate and merge related findings; each finding re-verified by the adversarial verifier (finder ≠ verifier).
- [x] Assign severity per Appendix C; map security findings to CVSS v4.0 and to the component risk ranking from Phase 0. *severity assigned per Appendix C; numeric CVSS v4 scoring substituted by the roadmap's severity × reachability × TCB-centrality ÷ effort prioritization (the P0/P1 set is small and action-ordered)*
- [x] Build the heat map: findings × component × phase; identify clusters (one root cause, many symptoms).
- [x] Close the loop on the hypotheses register (Section 9): every H confirmed, refuted, or refined — with evidence.
- [x] Draft `audit-report.md`: executive summary, methodology, per-phase results, risk view, testing-strategy scorecard, and the inputs to the Resolution Plan.

**Exit criteria.** No unverified P0/P1; every finding has severity, evidence, and suggested-fix pointer.
**Timebox.** 1 day.

---

### Phase 8 — Resolution Plan (Day 10)

**Objective.** Produce the session's closing artifact: the **Resolution Plan** — consecutive, ordered steps for resolving the audit's issues. Its framework (inputs, prioritization math, wave sequencing, acceptance gates, metrics) is defined in **Section 8** of this roadmap and is populated from the findings register during Day 10.

---

## 7. Severity taxonomy & findings register

| Severity | Definition | Resolution window (suggested) |
|---|---|---|
| **P0 — Blocker** | Wrong code emitted for a target; exploitable memory corruption; seed/supply-chain integrity break; CI gate bypass | Stop-the-bleeding, ≤ 48 h |
| **P1 — Critical** | Miscompilation on reachable paths; crypto side channel or validation gap; data-loss class bug; test-suite false-green | This sprint |
| **P2 — Major** | Material debt or delivery risk: perf cliffs, undocumented semantics, weak fuzzing, isolation hazards | This quarter |
| **P3 — Minor** | Quality/consistency gains: naming, dead code, comment drift | Backlog grooming |
| **Info** | Stylistic, future-proofing | Optional |

Register schema (Appendix B): ID · phase · component · file:line · title · description · evidence (reproducer or reasoning) · **design intent? (deliberate / accidental / unknown — see §4.1)** · **invariant touched (I1–I8 / none)** · severity · CVSS (if security) · confidence (confirmed/suspected) · suggested fix (proposal only, in-Sovren) · acceptance criteria · resolution-plan wave.

---

## 8. Resolution Plan (framework — populated at Phase 8)

The Resolution Plan is the session's final deliverable. It is built **only** from verified findings and follows this fixed structure:

**Step 1 — Triage.** Every finding gets severity (Section 7), blast radius (which targets/users), and dependency tags (e.g., "needs bounds redesign", "needs spec decision").

**Step 2 — Prioritize.** Sort by: (a) severity × reachability, (b) TCB centrality (seed → compiler → runtime → library → tooling), (c) fix effort. Plot on a severity×effort matrix; quick wins (high severity, low effort) jump the queue behind only P0s.

**Step 3 — Sequence into consecutive waves** (each wave is a resolvable unit with its own verification gate, and **every wave carries an invariant-preservation gate: no step may violate I1–I8 without an explicit design-decision record**):

| Wave | Theme | Typical contents (to be confirmed by findings) | Gate |
|---|---|---|---|
| **0 — Stop the bleeding** | P0s only | Wrong-codegen on any target; exploitable memory corruption; seed/provenance break; CI gate bypass | Full suite green on all three OS runners; bootstrap clean |
| **1 — Quick wins (week 1)** | High severity, low effort | RNG modulo bias + range-ceiling fix (in-Sovren); `/tmp` fixture isolation (`mktemp`); workflow SHA pinning; README + SECURITY policy; skip-list re-justification; stale-comment corrections (e.g., the spawn comment) | PR-gate suite + `fast` tier green; zero-warnings gate holds |
| **2 — Structural (weeks 2–4)** | Root causes | Bounds policy **documentation** (unchecked default stays, I4; `bounds.sov` is the documented safety path; explore compile-time-provable checks that add no default-path cost); in-language crypto CT remediation list; TLS cert-validation hardening; `vault` AAD fix; optional suite.sov decomposition preserving the one-battery property and no-build-system rule; per-target divergence guard (mechanical byte-diff of shared cores in CI) | Mutation pilot ≥ threshold on touched files; benchmark baseline re-captured; privacy board (pass 115) still green |
| **3 — Strategic (month 2+)** | Capability building | `fuzzlib` extension: corpus persistence, mutation operators, optional per-run seed (fixed seed stays the regression default, I7); emulator step-trace coverage feedback; EMI/metamorphic families; ARM differential vectors; in-Sovren mutation testing as a nightly gate; benchmark gates; seed provenance documentation + emulator-based seed verification (I2 — not regeneration); language reference doc; spec gap closure from Phase 4 | Maturity model level-up; defect-escape rate tracked |

**Step 4 — Assign.** Owner, reviewer, and verifier per step; external-contributor-safe items marked (PSVL permits community contribution).

**Step 5 — Define acceptance.** Every step carries a test-first requirement: *no fix lands without a failing check that it makes pass* (new probe, suite check, or differential vector), plus the regression gate it must survive.

**Step 6 — Verify & close.** Each fix re-enters CI on real Windows/macOS/Linux; security fixes re-run the Phase 2 spot checks; the findings register moves items to `closed` only on green evidence.

**Step 7 — Measure.** Success metrics: defect escape rate, suite wall time (≤ 105 s budget), flaky rate (≤ 1% ceiling), mutation score on core passes, benchmark deltas, time-to-first-compile for a newcomer.

**Step 8 — Iterate.** Resolution Plan is a living document: weekly re-triage, waves re-ordered as new evidence lands.

---

## 9. Pre-research hypotheses register (confirm, refute, or refine — with evidence)

| # | Hypothesis (from pre-research) | Phase |
|---|---|---|
| H1 | The 10 KB seed `sovren` binary is opaque and not regenerable in-repo — the root of the TCB | 0, 2 |
| H2 | `rand_below`/`rand_range` have modulo bias and a 256-value ceiling; crypto paths must be checked for use of these weak helpers | 1, 2 |
| H3 | Default-unchecked indexing makes memory corruption a default-off risk in libraries that skip `bounds.sov` | 1, 2 |
| H4 | The never-freeing bump allocator grows to the 64 MB ceiling; behavior at the ceiling and secret-residue exposure need quantification | 1, 3 |
| H5 | Hand-rolled crypto + TLS 1.2 client are unaudited; certificate-validation completeness in the DER walker is unknown; SHA-1 ships enabled | 2 |
| H6 | `vault.sov` GCM tag does not cover its header (its own comment says so) → `iters` work-factor tampering | 2 |
| H7 | Per-target compiler divergence risk despite `cx86`/`carm`; the "verbatim" claim needs mechanical verification | 4 |
| H8 | Fuzzer is narrow: LCG, fixed seeds, 300 programs, expression-only grammar, no coverage feedback | 5 |
| H9 | Meta-circularity: tests are written in the language under test; mitigation stack needs residual-risk quantification | 5 |
| H10 | Hardcoded `/tmp` fixture paths and `sleep`-based sync create parallel-CI collisions and flakiness | 5 |
| H11 | No coverage, mutation, or benchmark gates exist | 3, 5 |
| H12 | No README/spec/CONTRIBUTING; onboarding relies on source comments | 6 |
| H13 | Supply chain: committed binaries (proven fresh by bootstrap), tag-pinned actions, real-hardware runner dependence | 2, 6 |
| H14 | Global mutable state couples compiler passes and the shared cores; re-entrancy and testability costs | 4 |
| H15 | `suite.sov` (182 KB) is a monolith; the two-tier skip list needs governance | 4, 5 |
| H16 | Single-commit history: no archaeology, no blame path, no regression-bisect capability | 6 |
| H17 | Comment/code drift class exists — first confirmed instance: `runtime.sov` spawn comment forbids heap allocation in spawned jobs, but `_sov_alloc` carries an atomic spinlock (stale comment, not a race) | 1, 4 |
| H18 | Privacy invariant (I6) holds: compiler source is capability-free (no network/process/clock syscalls); no roadmap recommendation may add a capability | 2, 8 |

---

## 10. Risks to the audit itself (and mitigations)

| Risk | Mitigation |
|---|---|
| **Meta-circularity**: the compiler under test compiles its own tests | Independent oracles (hardware-derived vectors, RFC vectors, second emulator, native cross-compiled binaries); seed-binary cross-checks |
| **No SAST tooling knows `.sov`** | Custom grep/script sweeps (run from `/tmp`) + structured manual review; the codebase's strong comment culture is the primary navigation aid |
| **Emulator fidelity** is itself unproven | Differential vectors already exist for x86; extend to ARM; treat emulator-based conclusions as "as faithful as the emulator" |
| **Single commit** hides history-driven context | Interview-free archaeology: infer intent from comments (rich), CI YAML (very rich), and file provenance |
| **Real-hardware CI dependence** | Schedule dynamic checks around runner availability; keep a local fallback matrix |
| **Scope creep** | Timeboxes per phase; parking lot for out-of-scope findings; daily triage |

---

## Appendix A — Master checklists

### A.1 Correctness (Phase 1)
- [x] All syscall/IO return codes checked; failure messages actionable
- [x] Indexing sites enumerated; bounds usage classified per library
- [x] Arithmetic edges: overflow, div-by-zero, negative shifts, width assumptions
- [x] Parser edges: empty input, unterminated constructs, deep nesting, UTF-8, CRLF, NUL
- [x] Concurrency: spawn/join, alloc lock, race.sov false-negative classes
- [x] Target divergence: same program, six targets, consistent behavior
- [x] REPL state model; debugger line attribution
- [x] Launcher/CLI edge cases; flag conflicts

### A.2 Security (Phase 2)
- [x] STRIDE threat model documented
- [x] Crypto: CT inventory (source + binary), RNG quality, nonce/key handling, wipe coverage, PBKDF2 floors, SHA-1 exposure
- [x] TLS: cert validation completeness, downgrade resistance, PRF vectors
- [x] vault: AAD gap confirmed/refuted
- [x] Memory: unchecked indexing reachability, allocator ceiling, secret residue
- [x] Hardening: NX, PIE+reloc, dumpable-off, canary/wipe — independently re-derived
- [x] Supply chain: seed provenance, artifact freshness, workflow pinning
- [x] Secrets scan; license obligations

### A.3 Performance (Phase 3)
- [x] Compile-time scaling curves per target
- [x] Pass-level hot spots; super-linear algorithms
- [ ] Codegen quality spot checks (reg alloc, immediates, dead code) *partial: fiblike path only (F-29); register-allocation review deferred*
- [ ] Allocator growth to 64 MB ceiling; concat-in-loop costs; lock contention *partial: ceiling behavior measured — unenforced, 200 MB writable (F-57); concat measured (F-30); lock contention deferred*
- [x] Emulator steps/sec baseline and hot decode paths
- [x] Binary size per target; debug-map overhead
- [x] Benchmark determinism and gating

### A.4 Architecture (Phase 4)
- [x] Shared-core byte-identity verified mechanically
- [x] Global-state dependency graph; re-entrancy assessment
- [x] File/function size distribution; decomposition proposals
- [x] `use`-graph: cycles, layering violations, orphans
- [x] Error model consistency; message quality
- [x] Language semantics gaps logged as spec issues
- [x] Comment-truth spot audit; dead-code sweep

### A.5 Testing strategy (Phase 5)
- [x] Full test-asset inventory and taxonomy
- [x] Oracle classification (hardware / RFC / hand / self-reference)
- [x] Pyramid assessment; tier governance; skip-list review
- [x] Fuzzing maturity gap analysis
- [x] Differential/metamorphic/EMI coverage quantification
- [x] Coverage proxy proposal; mutation pilot
- [x] Isolation and determinism hazards
- [x] CI gating tiers, matrix completeness, signal quality
- [x] Meta-circularity residual risk statement
- [x] Historical bug-class regression coverage

### A.6 DX/docs/CI (Phase 6)
- [x] Time-to-first-compile measurement
- [x] Documentation truthfulness sample
- [x] Release engineering review (versioning, artifacts, changelog)
- [x] CI health (caching, pinning, lint, runner dependence)
- [x] Process hygiene (templates, CONTRIBUTING, SECURITY)

---

## Appendix B — Findings register template

| Field | Content |
|---|---|
| ID | F-<phase>-<nn> |
| Title | one line |
| Component | compiler-linux / compiler-windows / … / runtime / library:<name> / tests / ci / seed-binary |
| Location | `file:line` (plus function/pass) |
| Phase found | 0–6 |
| Description | what is wrong, precisely |
| Evidence | reproducer (`.sov` + observed vs expected) or reasoning chain |
| Impact | what breaks, for whom, how reachable |
| Severity | P0–Info (Section 7) |
| CVSS v4.0 | score + vector (security findings) |
| Confidence | confirmed / suspected |
| Suggested fix | proposal only — **no code changes in this session** |
| Acceptance criteria | the check that must pass after the fix |
| Resolution wave | 0–3 (Section 8) |
| Status | open / triaged / verifying / closed |

---

## Appendix C — Glossary (Sovren terms as used in this document)

- **Job** — a Sovren function (`name args:` … `return`).
- **`use <lib>`** — library import; resolution is compiler-enforced (unknown names are compile errors).
- **Pass** — one numbered compiler transformation stage (140+ observed).
- **Probe** — a focused compiler-behavior test in `tests/probes/`, named by pass family.
- **Check** — one unit of `suite.sov`: write program → compile → run → compare output.
- **Tier** — `all.sov` (full, ~105 s) vs `fast.sov` (skip list of 14 slow checks).
- **Seed** — the 10 KB `sovren` ELF that bootstraps the self-hosting chain.
- **Fixed point** — g3 == g4 == g5 byte-identity proof of the seed compiler.
- **Guest** — a binary loaded into the in-language x86/ARM emulator.
- **Task** — a spawned concurrent unit (own stack, shared globals).

---

## Appendix D — References (research consulted)

1. OWASP, *Secure Code Review Cheat Sheet* — https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html
2. Chen, Chen, Sui et al., *A Survey of Compiler Testing* (CSUR 2020) — https://www.software-lab.org/publications/csur2019_compiler_testing.pdf
3. Ma, *A Survey of Modern Compiler Fuzzing* (arXiv:2306.06884) — https://arxiv.org/pdf/2306.06884
4. Yang, Chen, Eide, Regehr, *Finding and Understanding Bugs in C Compilers* (PLDI 2011) — http://www-leland.stanford.edu/class/cs343/resources/finding-bugs-compilers-annotated.pdf
5. Poesia et al., *Compiler Fuzzing: How Much Does It Matter?* (OOPSLA 2019) — https://srg.doc.ic.ac.uk/files/papers/compilerbugs-oopsla-19.pdf
6. *SPECA: Specification-to-Checklist Agentic Auditing* (arXiv:2602.07513) — https://arxiv.org/html/2602.07513
7. Intel, *Guidelines for Mitigating Timing Side Channels Against Cryptographic Implementations* — https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/secure-coding/mitigate-timing-side-channel-crypto-implementation.html
8. *Breaking Bad: How Compilers Break Constant-Time Implementations* (arXiv:2410.13489) — https://arxiv.org/html/2410.13489
9. Blanchet et al., *SoK: Computer-Aided Cryptography* (Oakland 2021) — https://bblanche.gitlabpages.inria.fr/publications/BarbosaetalOakland21.pdf
10. Trail of Bits, *constant-time-analysis* skill — https://github.com/trailofbits/skills/blob/main/plugins/constant-time-analysis/skills/constant-time-analysis/SKILL.md
11. Wiz Academy, *What is code auditing?* — https://www.wiz.io/academy/application-security/code-auditing
12. Fora Soft, *What Is a Code Audit: Process, Tools & Cost* — https://www.forasoft.com/blog/article/what-is-code-auditing-and-how-to-conduct-it-evaluation-criteria-1673
13. Sonarsource, *Source code review: a comprehensive guide* — https://www.sonarsource.com/resources/library/source-code-review/
14. Devarmor, *How to audit source code for security* — https://www.devarmor.com/blog/audit-source-code
15. Cyberpress, *How modern source code audits strengthen architecture* — https://cyberpress.org/how-modern-source-code-audits-strengthen-architecture-for-high-load-and-safety-critical-systems/
16. Codelit, *Testing Strategy: From the Testing Pyramid to Chaos Engineering* — https://codelit.io/blog/testing-strategies-architecture
17. TotalShiftLeft, *Test Automation Best Practices for DevOps* (flaky-test ceilings, CI gate budgets) — https://totalshiftleft.ai/blog/test-automation-best-practices-devops
18. DevOpsSchool, *Test Pyramid metrics (M1–M3)* — https://www.devopsschool.nl/blog/test-pyramid/
19. Digital Applied, *Software Testing Strategy 2026* — https://www.digitalapplied.com/blog/software-testing-strategy-2026-engineering-reference

---

*End of roadmap. The session begins at Phase 0. No repository files were modified to produce this document.*
