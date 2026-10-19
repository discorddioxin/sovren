# Sovren Audit — Findings Summary (All Phases)

| | |
|---|---|
| **Repository** | `discorddioxin/sovren` — self-hosting systems language + six-target native compiler, written entirely in itself |
| **Freeze commit** | `003149e12777f19a3da2433066ddf3f1303da147` (single commit, "Placeholder") |
| **Audit window** | 2026-10-18, one session; host Linux 6.1.158+ x86-64 |
| **Ground rule** | Read-only: no repository source was modified; every fix below exists only as a proposal with acceptance criteria |
| **Citation standard** | Every finding cites `file:line` or an external authority (CWE / RFC / NIST / OWASP / Intel / SLSA / OpenSSF / PSVL) in the phase logs |

## The audit in brief

Sovren's engineering quality is high and its honesty invariants hold: the bootstrap rebuilds all ten toolchain artifacts byte-identically from a fixed seed, the 551-check battery is green (and was green twice more under mutation), the privacy board was independently re-derived and holds, and the source comments are unusually truthful (6 of 8 sampled claims exactly right). The audit found **51 findings — 1×P0, 11×P1, 24×P2, 15×P3 — plus 8 verified positives**, concentrated in three stories:

1. **The in-language TLS client is unsafe as it stands** (the only P0 and the largest cluster): a constant X25519 ephemeral key and constant ClientHello random make every session passively decryptable (F-01); certificates are never validated (F-02); the ClientHello carries no SNI and silently falls back to `/usr/bin/curl` (F-05); the ladder's conditional swap branches on the secret scalar (F-56); the RSA path branches on secret data (F-22); session keys are never wiped (F-24); AES is a secret-indexed table lookup (F-21); debug prints fire on every handshake (F-06); and nothing tests it end-to-end (F-04). The library's own header already says "not certified" — the audit's job is to make that disclaimer unnecessary.
2. **Silent cross-platform crypto failure**: on Windows, `getrandom` is not in the syscall bridge and `rand_bytes` never checks the return, so vault salts/nonces and session tokens are silently all-zero (F-58) — invisible to CI because the vault boards assert round-trips, never entropy (F-59). macOS is bridged correctly; only Windows is affected.
3. **The test battery is strong where it looks and blind where it doesn't**: hardware-derived x86 vectors, RFC/NIST crypto vectors, and byte-identity anchors are excellent, but 60 of 168 libraries have zero behavioral coverage (F-32), 225 library tasks are referenced nowhere (F-38), a mutation pilot proved 2/2 mutants survive — including a compiler-core mutant that provably miscompiles legal programs (F-35) — and the CI recursion benchmark is constant-folded at compile time (F-29).

## Document map

| Document | Content |
|---|---|
| `docs/AUDIT-ROADMAP.md` | Charter: phases, checklists (all completed items ticked), severity taxonomy, Resolution Plan framework, hypotheses H1–H18, invariants I1–I8 |
| `docs/PROGRAM-ANALYSIS.md` | Purpose/semantics analysis; the eight design invariants the audit must not harm |
| `docs/audit/findings-phase0-phase1.md` | Baselines + F-01…F-20 (correctness, defect hunt) |
| `docs/audit/findings-phase2-phase3.md` | F-21…F-35 (security, crypto CT, performance) + STRIDE table |
| `docs/audit/findings-phase4-phase5.md` | F-36…F-47 (architecture, testing strategy) + mutation pilots |
| `docs/audit/findings-phase6.md` | F-48…F-55 (DX, docs, CI, release) + documentation-truthfulness sample |
| `docs/audit/findings-verification-addendum.md` | F-56…F-60 (verification pass: full CT inventory, allocator ceiling, `mem.sov` sweep, adversarial re-verification of all P0/P1) |
| `docs/audit/audit-report.md` | Phase 7 synthesis: consolidated register, heat map, hypothesis closure, testing scorecard |
| `docs/audit/resolution-plan.md` | Phase 8: the Resolution Plan — triage, prioritization math, four waves with acceptance gates |

## Findings index (51)

**Phase 0–1 — baseline, correctness, defect hunt**

| ID | Sev | Component | Finding | Wave |
|---|---|---|---|---|
| F-01 | **P0** | tls.sov | Constant X25519 ephemeral key + constant ClientHello random → every session passively decryptable (proven live) | 0 |
| F-02 | P1 | tls.sov | Zero certificate validation (no expiry/hostname/chain/CA; proven live against a self-signed wrong-host cert) | 2 |
| F-03 | P1 | repo | Fresh clones broken: all tool binaries committed mode 100644; CI masks via a chmod ritual | 1 |
| F-04 | P1 | tests | Zero end-to-end TLS tests (suite has no `tl_get`/`tl_send` board) | 2 |
| F-05 | P1 | tls/web | 65-byte ClientHello, no SNI → in-language TLS fails on SNI hosts; silently masked by the curl fallback | 2 |
| F-06 | P2 | tls.sov | Debug prints fire on every handshake (`tls.sov:572, 649`) | 2 |
| F-07 | P2 | runtime.sov | `_sov_alloc` never checks `heap_end` — over-allocation writes past the mapping | 2 |
| F-08 | P2 | compilers | Stack exhaustion SIGSEGVs past the crash handlers (no sigaltstack) | 2 |
| F-09 | P2 | compilers | Quadratic compile time vs nesting depth (4 KB file ≈ 60 s) | 1 |
| F-10 | P2 | libraries | Raw Linux syscalls in shared libraries (`uid`, `walk`, `proc`, `file`, `perm`), no platform labels | 2 |
| F-11 | P2 | tests | Hardcoded `/tmp` fixture paths — concurrent-instance collision + symlink surface | 1 |
| F-12 | P2 | vault.sov | No PBKDF2 iteration floor (load rejects only `< 1`) | 1 |
| F-13 | P2 | compilers | Most diagnostics lack file:line despite `src_name`/`err_line` being tracked | 2 |
| F-14 | P3 | compilers | Out-of-range literals silently wrap (`99999999999999999999` → `7766279631452241919`) | 3 (spec decision) |
| F-15 | P3 | rand.sov | `rand_below` modulo bias (live 30k-sample distribution) + 256-value ceiling; latent | 1 |
| F-16 | P3 | docs | Comment drift (stale spawn comment; "211 KB seed" vs actual 225,144 B) | 1 |
| F-17 | P3 | compilers | Unactionable "Warning: locals" | 3 |
| F-18 | P3 | libraries | getent stderr leaks; TLS failures set no `web_last` reason | 3 |
| F-19 | P2 | fuzzer | Fuzzer immaturity (LCG, fixed seeds, 300 programs, expression-only grammar) | 3 |
| F-20 | P2 | suite.sov | 182 KB monolith (skip-list half retired by F-42) | 3 |

**Phase 2–3 — security, crypto, performance**

| ID | Sev | Component | Finding | Wave |
|---|---|---|---|---|
| F-21 | P1 | aes.sov | AES SubBytes is a secret-indexed S-box table lookup (variable-time) | 2 |
| F-22 | P1 | bigint/tls | Bigint reduction branches on secret data in the TLS RSA path (live once F-01 lands) | 0 |
| F-23 | P2 | gcm.sov | No atomic verify-then-decrypt; tag check is the caller's job (footgun; chachapoly shows the right pattern) | 2 |
| F-24 | P2 | tls.sov | TLS session keys never wiped (no `use secret`) | 2 |
| F-25 | P2 | cffi.sov | ELF-only FFI compiles on every target, header says nothing | 2 |
| F-27 | P1 | LICENSE | PSVL §3.3 requires private disclosure to the Author first — the plan must route security findings accordingly | 1 (process) |
| F-28 | P2 | compilers | Super-linear compile time in program size (50k statements → 8.1 s, ≈O(n^1.9)) | 1 |
| F-29 | P3 | tests/cx86 | CI recursion benchmark is constant-folded; runtime recursion never measured; fast path keyed on source-text shape | 2 |
| F-30 | P3 | string.sov | O(n²) concat-in-loop undocumented (20k concats = 738 ms; `buf.sov` is the answer) | 3 |
| F-32 | P2 | tests | 60 of 168 libraries have zero behavioral coverage (proven by mutation pilot M1) | 2 |
| F-33 | P3 | libraries | Mutual `use` cycle tls↔web | 3 |
| F-35 | P1 | tests | Mutation pilot: 2/2 mutants survived the 551-check battery; one provably miscompiles legal programs | 2 |

**Phase 4–5 — architecture, testing strategy**

| ID | Sev | Component | Finding | Wave |
|---|---|---|---|---|
| F-38 | P2 | libraries | 225 of 2,023 tasks in live libraries referenced nowhere — unverified API surface | 2 |
| F-39 | P3 | x86/arm.sov | 20 core tasks unreferenced, incl. 6 implemented-but-unreachable SSE/AVX handlers | 3 |
| F-40 | P3 | libraries | The language's own `assert`/`test` libraries are unused by its own battery | 3 |
| F-43 | P2 | tests | ARM emulator has no differential vector suite (x86 has 5,004 lines of them) | 3 |
| F-44 | P2 | suite.sov | Size concentration (cx86 315 KB, x86 304 KB, suite 178 KB, carm 121 KB); per-board decomposition proposal | 3 |
| F-47 | P2 | tests | Coverage proxy (emulator PC bitmap + pass counters) and nightly mutation gate proposed | 3 |

**Phase 6 — DX, docs, CI, release**

| ID | Sev | Component | Finding | Wave |
|---|---|---|---|---|
| F-48 | P1 | repo | Onboarding blocked on a fresh clone; time-to-first-compile is 16 ms *after* an undocumented chmod ritual; the error message names neither cause nor fix | 1 |
| F-49 | P2 | repo | No README, CHANGELOG, CONTRIBUTING, SECURITY.md, issue templates, or manifest | 1 |
| F-50 | P2 | legal/DX | License demands private disclosure first; the repo publishes no disclosure route | 1 |
| F-51 | P3 | repl.sov | Header overstates REPL cost ~200× ("a second or two" vs 5 ms measured) | 1 |
| F-52 | P3 | launcher.sov | `--help` never mentions the REPL or the committed debugger | 1 |
| F-53 | P3 | CI | No caching, floating runner images, no workflow-lint gate | 2 |
| F-55 | P3 | release | Artifact naming inconsistency (`compiler-so` vs `compiler`) | 3 |

**Verification addendum — CT inventory closure, ceiling measurement, adversarial re-verification**

| ID | Sev | Component | Finding | Wave |
|---|---|---|---|---|
| F-56 | **P1** | x25519.sov | The ladder's `x_cswap` branches on a secret-derived value — scalar bits leak through timing; the in-source comment misreads its own call graph | 0 |
| F-57 | P2 | runtime.sov | The documented 64 MB heap ceiling is enforced nowhere: 200 MB allocated and written live; behavior is host-layout-dependent | 2 |
| F-58 | **P1** | rand.sov + Windows compiler | Silent zero entropy on Windows: `getrandom` (318) absent from the `_sov_wincall` bridge (maps only {0,1,2,3,8,9,16,60}) and `rand_bytes` ignores the return — vault salts/nonces and tokens become all-zero; macOS bridges 318 correctly | 1+2 |
| F-59 | P2 | tests | Boards assert round-trips but never entropy — the oracle gap that hid F-58 on Windows CI | 2 |
| F-60 | P2 | libraries | Complete `mem.sov`-rule sweep: 29 libraries use raw `sys_*` wrappers; the platform-specific set needs labels | 2 |

## Verified positives (8)

- **F-26** Privacy board independently re-derived: capability-free output, no build metadata, NX stacks (PT_GNU_STACK RW), `prctl(PR_SET_DUMPABLE)` emitted iff `private` — all hold.
- **F-31** Performance: bench.sov's 2.9M-iteration loop in 5 ms with a known-answer check; fib(30) in 1 ms via the iterative fiblike path; hello.sov compiles to all targets in 2–10 ms.
- **F-34** Shared-core architecture verified: all x86 back ends `use cx86` with zero task collisions; the bootstrap fixed point proves the committed binaries match the sources.
- **F-36** SHA-1 ships with an explicit "legacy checksums, NOT for security" header — the honesty invariant applied to a deprecated primitive.
- **F-41** Global-state discipline is tight: 10 shared-mutable globals in the compiler core (branch bookkeeping), 2–4 per target layer; the rest is task-local.
- **F-42** Skip-list governance is sound: 14 skips, each justified in-header; new checks auto-run in both tiers; CI runs the full tier regardless.
- **F-45** Back-end hook contract consistent: all three x86 compilers expose the same five core-facing tasks.
- **F-54** Two-tier test design is self-documented and sound: self-contained `all.sov` gates every push; dependency-heavy `run.sov` runs weekly.

## Hypotheses register — final states (H1–H18)

Confirmed: H2 (RNG bias, F-15) · H4 (allocator; real defect is F-07/F-57) · H5 (crypto cluster, expanded) · H8 (fuzzer narrow, F-19) · H10 (isolation hazards, F-11) · H11 (no coverage/mutation/benchmark gates — proven empirically, F-35/F-29) · H12 (no README, F-49) · H16 (single-commit history) · H17 (comment drift, F-16/F-51) · H13 (partially: supply chain — artifacts proven fresh, pinning gaps F-37/F-53).
Confirmed as design intent (not bugs): H1 (seed opacity — I2; provenance documentation recommended) · H3 (unchecked indexing — I4).
Refuted: H6 (vault AAD gap — header fields are KDF inputs, tamper fails the tag) · H7 (per-target divergence at the core — F-34/F-45) · H14 (global-state coupling at the feared scale — F-41) · H15 (partially: skip governance sound, F-42; monolith size real, F-20/F-44).
Verified: H9 (meta-circularity mitigations; residual risk low-but-nonzero) · H18 (privacy invariant holds, F-26).

## The Resolution Plan at a glance

- **Wave 0 (≤ 48 h):** the TLS randomness cluster — F-01 + F-22 + F-56, sequenced together (a random ephemeral key makes the CT violations live), with a ClientHello differential regression guard.
- **Wave 1 (week 1):** quick wins — exec bits + README/SECURITY/CONTRIBUTING (F-03/F-48/F-49/F-50), compiler pass profiling + quadratic fix (F-09/F-28), `/tmp` fixture isolation (F-11), PBKDF2 floor (F-12), RNG bias (F-15), stale comments (F-16/F-51), SHA-pinned actions (F-37), help-text additions (F-52), rand return-check trap (F-58a), entropy boards (F-59).
- **Wave 2 (weeks 2–4):** structural — certificate validation + SNI (F-02/F-05), AES bitslicing (F-21), bigint CT reduction (F-22 verification), TLS key wiping (F-24), atomic GCM verify (F-23), heap-end trap (F-07/F-57), sigaltstack crash handlers (F-08), platform labels + Windows getrandom bridge (F-10/F-25/F-60/F-58b), diagnostic file:line (F-13), TLS end-to-end board (F-04), mutation gate + coverage proxy (F-35/F-47), orphan-library behavioral checks (F-32/F-38), runtime-arg benchmark (F-29), CI hygiene (F-53).
- **Wave 3 (month 2+):** strategic — literal-wrap spec decision (F-14 `[spec]`), fuzzer extension (F-19), ARM differential vectors (F-43), SSE-handler decision (F-39), suite decomposition (F-20/F-44), tls↔web decoupling (F-33), documentation polish (F-30/F-17/F-18/F-55), seed provenance (H1), dogfooding the unit-test libraries (F-40).

Every wave carries the invariant-preservation gate (no step may violate I1–I8 without a design-decision record) and the test-first rule (no fix lands without a failing check it makes pass). Full detail: `resolution-plan.md`.

## Invariant assessment

No suggested fix violates the purpose-protecting invariants: all are implementable in Sovren (I1); none regenerates the seed (I2); none breaks the shared-core model (I3); none adds default-path checks, GC, or bounds (I4); several increase honesty (I5); none adds a capability (I6); fuzzer recommendations keep the fixed regression seed (I7); all tooling extends in-Sovren tools (I8). Two findings required design-decision records before scheduling: F-14 (language semantics) and F-39 (dead code vs missing wiring).

## Reproducing this audit

Freeze commit `003149e…`; on a Linux x86-64 host: apply the CI chmod ritual (`git ls-files -z 'sovren' 'sovren.exe' 'compilers/' … | xargs chmod +x`), then `./sovren bootstrap.sov` (byte-identical rebuild), `./sovren tests/all.sov` (551 checks), and the reproducers described in each phase log (all runnable from `/tmp`, never committed). Dynamic checks were performed on Linux only; Windows/macOS behavior was verified statically against the bridge tables and via CI's documented assertions — F-58's dynamic Windows verification is the plan's first owed external check.

---

*End of summary. The audit session is complete: Phases 0–8 executed, 51 findings registered (1×P0, 11×P1, 24×P2, 15×P3), 8 positives verified, 18 hypotheses closed, and a four-wave Resolution Plan with acceptance gates. The repository source was never modified.*
