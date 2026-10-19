# Sovren Audit — Resolution Plan (Phase 8)

| | |
|---|---|
| **Session** | Audit of `discorddioxin/sovren` — closing artifact, per `docs/AUDIT-ROADMAP.md` §8 |
| **Inputs** | Consolidated register in `audit-report.md` §3 (51 findings: 1×P0, 11×P1, 24×P2, 15×P3; 8 verified positives) + the verification addendum (`findings-verification-addendum.md`, which closed the Phase 2 CT-inventory exit criterion) |
| **Status** | PROPOSAL ONLY. No repository source was modified at any point in this audit. Every step below is a suggestion with acceptance criteria. |
| **Legal gate (F-27/F-50)** | PSVL §3.3 (`LICENSE:99-100`) requires good-faith security research to be disclosed **privately to the Author first**. The security content of this plan (Waves 0–2, all TLS/crypto items) must be routed privately to the Author before any public publication. The repo publishes no disclosure route — adding one is step W1-7. |

---

## Step 1 — Triage

Blast radius: **TLS/crypto** = every session of every user (F-01 is total compromise of confidentiality); **compiler cores** = every program, every target; **runtime** = every program; **libraries** = opt-in users; **tests/CI** = project-internal trust.

Dependency tags: `[CT]` constant-time discipline · `[I4]` must preserve unchecked-by-default speed · `[I1]` must be implementable in Sovren · `[spec]` needs a design-decision record (roadmap §4.1) · `[test-first]` no fix lands without a failing check.

## Step 2 — Prioritization

Score = severity × reachability × TCB-centrality ÷ effort. The matrix:

| | Low effort | High effort |
|---|---|---|
| **High severity, high reach** | F-03/48, F-15, F-12, F-11, F-37, F-49, F-50, F-52, F-16/51 | **F-01+F-22** (do first anyway — P0), F-02, F-05, F-21, F-24 |
| **High severity, low reach** | F-04 (with the TLS cluster) | F-08, F-35/F-47 |
| **Low severity, high reach** | F-09, F-28, F-13, F-06 | F-19, F-43, F-44 |
| **Low severity, low reach** | F-30, F-51, F-55 | F-39, F-14 `[spec]`, F-40 |

## Step 3 — Waves

**Every wave carries the invariant-preservation gate (roadmap §8): no step may violate I1–I8 without an explicit design-decision record, and every step is test-first — the fix lands with the failing check it makes pass.**

### Wave 0 — Stop the bleeding (≤ 48 h)

| # | Finding(s) | Step (suggestion, in-Sovren `[I1]`) | Acceptance gate |
|---|---|---|---|
| W0-1 | **F-01** (P0) + **F-22** (P1, sequenced) | Make the TLS client draw its ephemeral X25519 key and ClientHello random from `sys_getrandom` (the kernel RNG `rand.sov` already uses for bytes — `rand.sov` header) instead of the constant `(i*13+5)%256` / `(i*7)%256` generators (`tls.sov:554-560`, `:336-340`); in the same change, make the bigint reduction path secret-independent: fixed-width normalization (no `bi_trim` loop on secrets, `bigint.sov:32-40`) and constant-time comparison in reduction (`bi_cmp`, `:97-110`) `[CT]` | A new suite board: two consecutive `tl_client` handshakes against a local mock server (the `check.yml` mock-server pattern) produce **different** ClientHello randoms and different ephemeral keys; a step-trace variance probe (emulator, two different premasters) shows no timing separation; full battery green |
| W0-2 | F-01 regression guard | Add the captured-ClientHello differential to the privacy board: compile a TLS-using program, scan the emitted binary for the constant-random pattern (the pass-115 scanner pattern, `suite.sov:2152+`) | The new check fails on the pre-fix source and passes after |

*Invariant gate:* randomness from the kernel RNG adds no capability (I6 — `getrandom` is already used by `rand.sov`); no default-path cost (I4); self-contained (I1).

| W0-3 | **F-56** (P1) | Replace the branch in `x_cswap` (`x25519.sov:286-298`) with a limb-wise mask swap using the existing `wand`/`wxor` primitives (the pattern `poly1305.sov`/`gcm.sov` already use): `mask: 0 - sw; t: wand(mask, wxor(a_i, b_i)); a_i: wxor(a_i, t); b_i: wxor(b_i, t)` — no branch on the secret-derived `sw` `[CT]` | Emulator step-trace variance probe across two different scalars shows no timing separation; the existing X25519 known-answer checks still pass |

### Wave 1 — Quick wins (week 1)

| # | Finding(s) | Step | Acceptance gate |
|---|---|---|---|
| W1-1 | F-03/F-48 (P1) | Correct git modes on the ten tool binaries (`git update-index --chmod=+x`); add a README quickstart; launcher prints the exact `chmod` command if it cannot exec the compiler (`launcher.sov`, the "could not start the compiler" path) | Fresh clone → `./sovren tests/hello.sov -o /tmp/x` works with zero manual steps; the failure message (when it occurs) names the cause and the fix |
| W1-2 | F-09, F-28 (P2) | Instrument compiler-pass timings (the `tr_time` pattern, `testrun.sov:24-40`); profile the 1k/10k/50k-statement and 250/500/1000-deep curves; fix the first quadratic structure found (candidate: the resolver's linear `idx` scan, `cx86.sov:5553-5560`); add a nesting-depth advisory limit | Re-measured curves are ≤ O(n log n) or the limit fires with a named error; compile-time regression check added to `bench.sov` |
| W1-3 | F-11 (P2) | Replace hardcoded `/tmp/sov-*` fixtures with `time_ms`-suffixed unique paths (`time.sov`; already suite-deployed on all three OS runners) | Two concurrent suite runs on one host both pass green |
| W1-4 | F-12 (P2) | Enforce a PBKDF2 iteration floor (suggested ≥ 100,000, OWASP Password Storage Cheat Sheet) in `vault_load` (`vault.sov:93-95`), warning (not rejecting) legacy vaults below the floor | A vault saved with `iters < floor` loads with a warning; the floor is a named constant in the header |
| W1-5 | F-15 (P3) | Fix `rand_below` modulo bias with rejection sampling and raise the 256-value ceiling (combine `rand_u8` calls) | The live distribution test (30,000 samples) shows no bias beyond ±1%; the fix is internal — no caller changes |
| W1-6 | F-16/F-51 (P3) | Correct the three stale comments (`runtime.sov` spawn comment, "211 KB seed" → 225,144 B, `repl.sov:13-15` cost → measured 5 ms/line) | Comment-truth spot check re-run: 9/9 sampled claims true |
| W1-7 | F-27, F-49, F-50 (P1/P2) | Add README (what/quickstart/target matrix/honesty note), `SECURITY.md` (private-disclosure route per PSVL §3.3), `CONTRIBUTING.md` (`LICENSE:302` permits community contribution), CHANGELOG seed | A stranger can reach a working compiler from the repo root with no prior knowledge |
| W1-8 | F-37, F-53 (P3) | SHA-pin `actions/checkout` (5 sites); add `actionlint` step; document runner-image policy | `grep "uses:" .github/workflows/*.yml` shows only SHA-pinned refs; actionlint runs clean |
| W1-9 | F-52 (P3) | Two lines in `lc_help` (`launcher.sov:21-42`): the REPL (`./sovren repl.sov -o repl && ./repl`) and the debugger (`sovren-dbg`) | `--help` mentions both; verified by a suite check on the help text |
| W1-10 | F-58a (P1) | `rand_bytes` traps when `sys_getrandom` returns < 0 (`rand.sov:5-7`) — no silent fallback anywhere (I5) | A mock-syscall failure board traps with a named reason instead of returning zeros |
| W1-11 | F-59 (P2) | Entropy boards: two `vault_save` calls (same input+password) → different ciphertexts; 100 `token_new` draws → 100 distinct values; `auth` salts differ | Boards fail pre-fix on Windows, pass after W2-8b; green everywhere post-fix |

*Invariant gate:* none of W1 adds capabilities (I6), default-path checks (I4), or external dependencies (I1).

### Wave 2 — Structural (weeks 2–4)

| # | Finding(s) | Step | Acceptance gate |
|---|---|---|---|
| W2-1 | F-02, F-05 (P1) | Implement certificate validation in the DER walker: expiry, hostname match, chain-to-trusted-root, and a CA store (in-repo, self-contained `[I1]`); extend the ClientHello to carry SNI (hostname from the URL) and a realistic extension block; remove or gate the `/usr/bin/curl` fallback in `web.sov:275-295` with an explicit warning when it fires (I5 honesty) | Suite board: self-signed / wrong-hostname / expired certificates are all **rejected** with named reasons; an SNI-only host (e.g., a local mock with SNI) fetches successfully in-language; the fallback event is user-visible |
| W2-2 | F-21 (P1) `[CT]` | Bitslice AES SubBytes (or document the limitation plainly per I5 if bitslicing is rejected) | Source-level CT inventory classifies every crypto path; the AES hot loop has no secret-indexed lookup; emulator step-trace variance probe shows no separation across two plaintexts |
| W2-3 | F-24 (P2) | Wipe TLS handshake buffers (`ep`, `pm`, `ms`, `sk`, `rk`) at the end of `tl_client` via `secret.sov`'s wipe family; mark the job `private` (arms the dumpable-off path, `secret.sov:14-17`) | Heap scan after a handshake (the suite's wipe-scanner pattern) finds no residual key material |
| W2-4 | F-23 (P2) | Add `gm_dec_verify` to `gcm.sov` — atomic verify-then-decrypt mirroring `chachapoly.sov:114` | Tampered-ciphertext check returns an error, never plaintext; vault migrates to the atomic call |
| W2-5 | F-06 (P2) | Remove the two stray handshake prints (`tls.sov:572`, `:649`) or gate them behind a debug flag | A handshake produces no stdout noise (the "3\n0" prefix is gone) |
| W2-6 | F-07 (P2) | Check `heap_end` in `_sov_alloc` and trap cleanly (the runtime's own trap path, "trap" exit 1) instead of writing past the mapping | The 64 MB over-allocation reproducer exits with the named trap, not silent success |
| W2-7 | F-08 (P2) | Install the crash handlers on a sigaltstack (`sys.sov` already exposes the needed syscalls) so stack exhaustion reports and wipes private frames | Deep-recursion reproducer (previously bare SIGSEGV/139) prints the named crash reason and exits via the wipe path |
| W2-8 | F-10/F-25/F-60 (P2) | Platform-label the raw-syscall libraries (the 29-library sweep table in the addendum §1/F-60 is the worklist: `uid`, `walk`, `proc`, `file`, `perm`, `cffi`, `dir`, `os`, `pipe`, `sock`, `key`, `line`, `term`, `termkit`, `tui`, `winx11`, …); compiler warns when a target-unsupported syscall is referenced | Cross-compiling a user of `walk` for Windows emits the named warning; headers state the platform |
| W2-8b | F-58b (P1) | Extend the Windows `_sov_wincall` bridge (`compilers/windows/compiler.sov:1643-1724`, currently {0,1,2,3,8,9,16,60}) with syscall 318 → `BCryptGenRandom`/`RtlGenRandom`, following the existing dispatcher pattern; macOS already bridges 318 (`compilers/macos/compiler.sov:1867`) | The F-58 acceptance test passes on a real Windows runner: two vault saves with identical input+password produce different ciphertexts |
| W2-8c | F-57 (P2) | Check `heap_ptr + size > heap_end` in `_sov_alloc` (`runtime.sov:43-50`) and trap through the runtime's named-trap path | The 200-chunk reproducer traps with a named reason at chunk 64; a suite board pins it |
| W2-9 | F-13 (P2) | Route the remaining diagnostics through the tracked `src_name`/`err_line` (`compiler.sov:58-59, 2551`) | Every compiler diagnostic names file:line; the arity-error vs name-error inconsistency (Phase 1) is gone |
| W2-10 | F-04, F-35, F-47 (P1/P2) | TLS end-to-end board (mock server, real handshake, known-answer); nightly in-Sovren mutation gate (mutate `.sov` text → rebuild via seed → run battery → kill-rate report); coverage proxy (emulator PC bitmap per check + pass-hit counters per probe) | Mutation kill-rate on the compiler core and crypto board reaches 100% before merges; coverage report exists per check |
| W2-11 | F-32, F-38 (P2) | Behavioral checks for the 60 orphan libraries and the 225 unreferenced tasks, highest-value first (`dict`, `toml`, `tsv`, `csv`, `uid`, `perm`, `date`, `stats`) | `tr_every_lib_checks` upgraded from build-only to build-and-run; kill-rate for library mutants > 0 |
| W2-12 | F-29 (P3) | Add a runtime-argument recursion benchmark (n from `argv`, defeating the compile-time fold) to `tests/bench.sov` or CI | CI measures actual recursive-call throughput; the fiblike shape-matching boundary is pinned by a check (a `< 3`-based fib compiles correctly — the M2 mutant's live behavior) |
| W2-13 | F-53 (P3) | Runner-image policy (pin where the platform allows); dependency cache for the weekly job | Workflow metadata reviewed; weekly job time recorded |

*Invariant gate:* cert validation adds no default-path cost to non-TLS programs (I4); the CA store is in-repo (I1); no telemetry or phone-home anywhere (I6).

### Wave 3 — Strategic (month 2+)

| # | Finding(s) | Step | Acceptance gate |
|---|---|---|---|
| W3-1 | F-14 `[spec]` | Design-decision record for out-of-range literals: keep wrap (documented) vs error vs warning. Recommend: warning at compile time, wrap at runtime (honest, no speed cost `[I4]`) | DDR recorded; chosen behavior tested |
| W3-2 | F-19 | Extend `fuzzlib.sov`: statement-level grammar, corpus persistence, mutation operators, optional per-run seed (fixed seed remains the regression default `[I7]`) | Fuzzer finds a seeded-in bug in a trial run; corpus persists across runs |
| W3-3 | F-43 | Port the x86 vector-harness shape to ARM (`arm_why`/`arm_result` helpers already exist, `arm.sov`) | ARM differential boards run in CI; the four unreferenced ARM helpers become exercised |
| W3-4 | F-39 | Maintainer decision on the 6 SSE/AVX handlers: wire the decoder + add vectors, or delete; same for `x86_used_syscall` | Either vector boards exist for the SSE instructions or the handlers are gone |
| W3-5 | F-20, F-44 | Split `suite.sov` per board into `use`d files (no build step introduced `[I1]`); the ordering file stays the one battery | Battery count unchanged (551→551+new); wall time within the ≤105 s budget |
| W3-6 | F-33 | Extract `web_lookup` into a leaf library; break the tls↔web cycle | Use-graph re-run: no mutual cycles among libraries |
| W3-7 | F-30, F-17, F-18, F-40, F-55 | Document the O(n²) concat pattern (point to `buf.sov`); make "Warning: locals" name the variables; give TLS failures a `web_last` reason; dogfood `assert.sov` in per-library checks; rename `compiler-so` → `compiler` | Each verified by its own check or spot-audit |
| W3-8 | H1 | Seed provenance documentation + emulator-based behavioral verification of the seed (never regeneration — I2) | A suite board verifies seed behavior under the in-language emulator; provenance note in README |
| W3-9 | F-40 | Adopt `assert.sov`/`test.sov` inside the battery's per-library checks (or document why `testrun` remains the framework) | The shipped unit-test libraries are exercised by the project that ships them |

## Step 4 — Assign

Roles per the roadmap §5: audit lead (triage/verifier), compiler reviewer (W0-1, W1-2, W2-2, W2-6…W2-9, W2-12), security reviewer (W0, W2-1…W2-5), testing/DX reviewer (W1-3, W2-10, W2-11, W3-2…). External-contributor-safe (PSVL permits it, `LICENSE:302`): W1-6, W1-7, W1-9, W3-5, W3-7 — all documentation, naming, and test-addition work.

## Step 5 — Acceptance (standing rule)

No fix lands without (a) a check that fails before it and passes after, (b) the full battery green on all three real-hardware OS runners, (c) the privacy board (pass 115) still green, and (d) for Waves 0–2 security items, the Phase 2 spot checks re-run (ClientHello capture, self-signed-cert rejection, binary capability scan).

## Step 6 — Verify & close

Each fix re-enters CI; security fixes re-run the Phase 2 dynamic reproducers; the register moves items to `closed` only on green evidence. The two design-decision records (F-14, F-39) close their `[spec]` tags before their waves start.

## Step 7 — Measure

Success metrics: defect escape rate (mutation kill-rate → 100% on core+crypto); suite wall time ≤ 105 s budget; flaky rate ≤ 1% ceiling; benchmark deltas vs the Phase 3 baselines (bench 5 ms, fib(30) 1 ms, hello compile 2–10 ms); time-to-first-compile → **0 manual steps**; TLS boards green.

## Step 8 — Iterate

The plan is living: weekly re-triage, waves re-ordered as evidence lands, and any new finding enters through the same register schema (roadmap Appendix B) with the same citation standard.

---

*End of the audit session. Deliverables: `docs/AUDIT-ROADMAP.md` (charter, checklists updated), `docs/PROGRAM-ANALYSIS.md` (purpose/invariants), `docs/audit/findings-phase0-phase1.md`, `findings-phase2-phase3.md`, `findings-phase4-phase5.md`, `findings-phase6.md`, `audit-report.md` (Phase 7 synthesis), and this plan. The repository's source was never modified; `git status` shows only the new `docs/` files.*
