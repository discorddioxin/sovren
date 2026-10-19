# Sovren Audit — Synthesis & Verification (Phase 7)

| | |
|---|---|
| **Session** | Audit of `discorddioxin/sovren` per `docs/AUDIT-ROADMAP.md` — synthesis of Phases 0–6 |
| **Freeze commit** | `003149e12777f19a3da2433066ddf3f1303da147` |
| **Evidence base** | `docs/audit/findings-phase0-phase1.md`, `findings-phase2-phase3.md`, `findings-phase4-phase5.md`, `findings-phase6.md`; `docs/PROGRAM-ANALYSIS.md`; `docs/AUDIT-ROADMAP.md` |
| **Ground rule held** | No repository source was modified at any point; every fix in this session exists only as a proposal |

---

## 1. Executive summary

Sovren is a complete, dependency-free, self-hosting native toolchain: a systems language, six-target compiler chain written entirely in itself, a 168-library standard library with hand-rolled crypto and a TLS 1.2 client, and an in-language x86-64/AArch64 emulator pair — all under a source-visible proprietary license that explicitly permits security auditing (`LICENSE:29-30`).

**The toolchain's engineering quality is high and its honesty invariants hold.** The bootstrap reproduces all ten artifacts byte-identically from a fixed seed (Phase 0); the 551-check battery is green and was re-verified green twice under mutation (Phase 2–3 session); the privacy board — capability-free compiler output, no build metadata, NX stacks, conditional `PR_SET_DUMPABLE` — was independently re-derived and holds (F-26); the shared-core architecture is structurally sound (F-34, F-45); the comment culture is unusually truthful (6 of 8 sampled claims exactly true, Phase 6 §2).

**The dominant risk is one cluster: the in-language TLS client.** F-01 (P0, constant X25519 ephemeral key + constant ClientHello random → passive decryption of every session), F-02 (zero certificate validation), F-05 (65-byte ClientHello, no SNI → silent `curl` fallback), F-06 (debug prints in every handshake), F-22 (secret-dependent branches in the RSA path), F-24 (key material never wiped). Six findings, one component, one fix program. The library's own header already disclaims production use (`tls.sov:2`) — the audit's job is to make that disclaimer unnecessary or the gaps impossible.

**The second risk is testing-oracle coverage.** 60 of 168 libraries have zero behavioral tests (F-32); 225 library tasks are referenced nowhere (F-38); a mutation pilot proved 2/2 mutants — including a compiler-core mutant that miscompiles legal programs — survive the battery (F-35); the ARM emulator has no differential vector suite (F-43); the CI recursion benchmark is constant-folded (F-29).

**Tally:** 51 findings — 1×P0, 11×P1, 24×P2, 15×P3 — plus 8 verified positive observations. All P0/P1 carry live reproducers or binary-level re-derivation. The Resolution Plan (`resolution-plan.md`) sequences everything into four invariant-preserving waves. A verification addendum (`findings-verification-addendum.md`) later closed the parked items and the Phase 2 CT-inventory exit criterion, adding five findings (F-56…F-60, two of them P1: a secret-dependent branch in the X25519 ladder, and silent zero entropy on Windows).

## 2. Methodology and verification standard

- **Phased execution** per the roadmap (Phases 0–6), each with its own exit criteria; every dynamic check ran from the frozen commit on a recorded host (Linux 6.1.158+ x86-64).
- **Evidence standard:** every finding cites `file:line` or an external authority (CWE / RFC / NIST / OWASP / Intel / SLSA / OpenSSF / PSVL). Reproducers for all dynamic findings live in `/tmp` and are described in the phase logs.
- **Adversarial verification** (roadmap §4): the privacy invariant was re-derived independently of the suite's own checks (F-26); the bootstrap fixed point was re-run; the mutation pilots were proven *live* before being declared survivors (a legal program compiled to a wrong answer under the mutant compiler); every P0/P1 was re-derived from its evidence chain before entering this report.
- **Meta-circularity guard:** tests are Sovren programs compiled by the compiler under test — mitigated by hardware-derived x86 vectors, RFC/NIST crypto vectors, the second emulator, and the bootstrap byte-identity anchor; residual risk assessed low-but-nonzero (Phase 5 §2).

## 3. Consolidated findings register (deduplicated)

Merge notes: **F-03 ≡ F-48** (one root cause: git mode bits; fix once). **F-10 ≡ F-25** (platform-specific code without header labels). **F-20/F-44** share a theme; the skip-list half of F-20 is retired by F-42 (governance verified sound). **F-32/F-38** quantify the same gap two ways. **F-27/F-50** are one legal/DX gap.

| ID | Sev | Component | Title | Wave |
|---|---|---|---|---|
| F-01 | **P0** | library/tls.sov | Constant X25519 ephemeral key + constant ClientHello random — every session passively decryptable | 0 |
| F-02 | P1 | library/tls.sov | Zero certificate validation (no expiry/hostname/chain/CA) | 2 |
| F-03/F-48 | P1 | repo root | Fresh clones broken (binaries mode 100644); first command fails with a misleading error | 1 |
| F-04 | P1 | tests | Zero end-to-end TLS tests | 2 |
| F-05 | P1 | library/tls.sov + web.sov | 65-byte ClientHello, no SNI; in-language TLS fails on SNI hosts, silently masked by curl fallback | 2 |
| F-21 | P1 | library/aes.sov | AES SubBytes is a secret-indexed table lookup (variable-time) | 2 |
| F-22 | P1 | library/bigint.sov + tls.sov | Bigint reduction branches on secret data in the TLS RSA path (live once F-01 lands) | 0 (with F-01) |
| F-27 | P1 | LICENSE | PSVL §3.3 requires private disclosure first — Resolution Plan must route security findings accordingly | 1 (process) |
| F-35 | P1 | tests | Mutation pilot: 2/2 mutants survived the 551-check battery (one provably miscompiling) | 2 |
| F-06 | P2 | library/tls.sov | Debug prints fire on every handshake | 2 |
| F-07 | P2 | runtime.sov | `_sov_alloc` never checks `heap_end` — over-allocation writes past the mapping | 2 |
| F-08 | P2 | compilers | Stack exhaustion SIGSEGVs past the crash handlers (no sigaltstack) | 2 |
| F-09 | P2 | compilers | Quadratic compile time vs nesting depth (4 KB file ≈ 60 s) | 1 |
| F-10/F-25 | P2 | library | Raw Linux syscalls / ELF-only FFI in shared libraries, no platform labels (uid, walk, proc, file, perm, cffi) | 2 |
| F-11 | P2 | tests | Hardcoded `/tmp` fixture paths — concurrent-instance collision + symlink surface | 1 |
| F-12 | P2 | library/vault.sov | No PBKDF2 iteration floor (load rejects only `< 1`) | 1 |
| F-13 | P2 | compilers | Most diagnostics lack file:line despite `src_name`/`err_line` being tracked | 2 |
| F-19 | P2 | tools | Fuzzer immaturity (LCG, fixed seeds, 300 programs, expression-only grammar) | 3 |
| F-20 | P2 | tests | suite.sov 182 KB monolith (skip-list half retired by F-42) | 3 |
| F-23 | P2 | library/gcm.sov | No atomic verify-then-decrypt; tag check is the caller's job | 2 |
| F-24 | P2 | library/tls.sov | TLS session keys never wiped (no `use secret`) | 2 |
| F-28 | P2 | compilers | Super-linear compile time in program size (50k statements → 8.1 s, ≈O(n^1.9)) | 1 |
| F-32 | P2 | tests | 60/168 libraries have zero behavioral coverage | 2 |
| F-38 | P2 | library | 225/2,023 tasks in live libraries referenced nowhere — unverified API surface | 2 |
| F-43 | P2 | tests | ARM emulator has no differential vector suite | 3 |
| F-44 | P2 | tests | Size concentration (cx86 315 KB, x86 304 KB, suite 178 KB, carm 121 KB); decomposition proposal | 3 |
| F-47 | P2 | tests | Coverage proxy (emulator PC bitmap + pass counters) and nightly mutation gate proposed | 3 |
| F-49 | P2 | repo root | No README/CHANGELOG/CONTRIBUTING/SECURITY/templates/manifest | 1 |
| F-50 | P2 | legal/DX | License demands private disclosure; repo publishes no route | 1 |
| F-14 | P3 | compilers | Out-of-range literals silently wrap | 3 (spec decision) |
| F-15 | P3 | library/rand.sov | `rand_below` modulo bias + 256-value ceiling (latent — no internal callers) | 1 |
| F-16/F-51 | P3 | docs | Comment drift (spawn comment, "211 KB seed", REPL cost 200× stale) | 1 |
| F-17 | P3 | compilers | Unactionable "Warning: locals" | 3 |
| F-18 | P3 | library | getent stderr leaks; TLS failures set no `web_last` reason | 3 |
| F-29 | P3 | tests + cx86.sov | CI recursion benchmark is constant-folded; fast path keyed on source-text shape | 2 |
| F-30 | P3 | library/string.sov | O(n²) concat-in-loop undocumented (buf.sov is the answer) | 3 |
| F-33 | P3 | library | Mutual `use` cycle tls↔web | 3 |
| F-37 | P3 | CI | Actions tag-pinned, not SHA-pinned | 1 |
| F-39 | P3 | library/x86.sov, arm.sov | 20 core tasks unreferenced, incl. 6 SSE/AVX handlers (dead or unwired) | 3 |
| F-40 | P3 | library | assert.sov/test.sov unused by the battery (dogfooding gap) | 3 |
| F-52 | P3 | launcher.sov | REPL and debugger absent from `--help` | 1 |
| F-53 | P3 | CI | No caching, floating runner images, no workflow lint | 2 |
| F-55 | P3 | release | Artifact naming inconsistency (`compiler-so`) | 3 |
| F-56 | P1 | library/x25519.sov | Ladder's conditional swap branches on a secret-derived value (timing leak of the scalar) | 0 (with F-01) |
| F-57 | P2 | runtime.sov | The 64 MB heap ceiling is enforced nowhere — 200 MB allocated and written; host-layout-dependent behavior | 2 |
| F-58 | P1 | rand.sov + windows compiler | Silent zero entropy on Windows: `getrandom` unmapped in the bridge, return unchecked — vault salts/nonces and tokens become all-zero | 1+2 |
| F-59 | P2 | tests | Boards assert round-trips but never entropy — the oracle gap that hid F-58 | 2 |
| F-60 | P2 | library | Complete `mem.sov`-rule sweep: 29 libraries use raw `sys_*` wrappers; platform-specific set needs labels | 2 |

**Verified positives (F-26, F-31, F-34, F-36, F-41, F-42, F-45, F-54):** privacy board re-derived; performance excellent (bench 5 ms / fib(30) 1 ms, correct); shared-core architecture verified; SHA-1 honestly labeled; global-state discipline tight; skip-list governance sound; back-end hook contract consistent; two-tier test design self-documented and sound.

## 4. Heat map — findings × component × severity

| Component | P0 | P1 | P2 | P3 | Total |
|---|---|---|---|---|---|
| TLS / crypto (tls, aes, bigint, gcm, vault, rand, x25519) | 1 | 5 | 5 | 1 | 12 |
| Compilers & cores (cx86, carm, 6 back ends) | — | — | 4 | 2 | 6 |
| Runtime (runtime.sov) | — | — | 3 | — | 3 |
| Libraries (platform & API surface) | — | — | 3 | 2 | 5 |
| Tests & tooling (suite, fuzz, emulators) | — | 2 | 5 | 5 | 12 |
| CI / release / supply chain | — | — | 1 | 3 | 4 |
| DX / docs / repo surface | — | 1 | 3 | 3 | 7 |
| Legal (LICENSE) | — | 1 | 1 | — | 2 |
| **Total** | **1** | **11** | **24** | **15** | **51** |

The TLS/crypto row carries the only P0 and the highest TCB centrality; the tests row carries the most items but only P1 is F-35 (false-green risk).

## 5. Hypothesis closure (H1–H18, final)

| H | Verdict | Evidence |
|---|---|---|
| H1 seed opacity | confirmed-as-design | I2; provenance documentation recommended (Wave 3) |
| H2 RNG modulo bias | confirmed | F-15 (live distribution 10043/9868/10089) |
| H3 unchecked indexing | confirmed-as-design-intent | I4; no internal-caller harm found; documentation only |
| H4 allocator ceiling | confirmed-as-design | F-07 is the real defect (no `heap_end` check) |
| H5 crypto unaudited | confirmed, expanded | F-01/02/05/06/21/22/23/24 |
| H6 vault AAD gap | refuted as practical risk | header fields are KDF inputs → tamper fails the tag |
| H7 per-target divergence | refuted at core level | F-34, F-45, bootstrap fixed point |
| H8 fuzzer narrow | confirmed | F-19 |
| H9 meta-circularity | mitigated, residual low-nonzero | Phase 5 §2; F-47 |
| H10 isolation hazards | confirmed | F-11; fix mechanism validated (`time_ms` suffixes) |
| H11 no coverage/mutation/benchmark gates | confirmed empirically | F-35 (2/2 mutant survivors), F-29, F-47 |
| H12 no README/spec | confirmed | F-49 |
| H13 supply chain | partially confirmed | artifacts proven fresh; F-37, F-53 remain |
| H14 global-state coupling | largely refuted at feared scale | F-41 (10 shared globals, purposeful) |
| H15 suite monolith / skip governance | split verdict | F-42 sound governance; F-20/F-44 size real |
| H16 single-commit history | confirmed | one commit; no archaeology possible |
| H17 comment drift | confirmed | F-16, F-51 (three instances) |
| H18 privacy invariant | verified independently | F-26 |

## 6. Testing-strategy scorecard (Phase 5 summary)

| Dimension | State | Grade |
|---|---|---|
| Oracle strength (top) | byte-identity, spec vectors, hardware differential (x86) | A |
| Oracle strength (bottom) | build-only checks, orphan libraries, self-authored expectations | C− |
| Pyramid shape | integration-shaped by design (I8); unit tier exists but unused (F-40) | B |
| Mutation quality | 2/2 pilot mutants survived (F-35) | D (today) |
| Differential coverage | x86 strong; ARM absent (F-43) | B− |
| Isolation / determinism | `/tmp` collisions (F-11); fixed seeds (I7) | C+ |
| CI gating | real-hardware matrix, zero-warnings, every-library | A− |
| Benchmark hygiene | known-answer gated; no timing gate; recursion check folded (F-29) | C+ |

## 7. Invariant-preservation assessment (I1–I8)

No finding's suggested fix violates the purpose-protecting invariants: all fixes are implementable in Sovren (I1); none regenerates the seed (I2); none breaks the shared-core model (I3); none adds default-path checks, GC, or bounds in the fast path (I4); several fixes *increase* honesty (I5: platform labels, REPL cost, disclosure route); none adds a capability (I6); fuzzer recommendations keep the fixed seed as the regression default (I7); all tooling proposals extend in-Sovren tools (I8). Two findings required design-decision records before entering the plan: F-14 (literal wrap — language semantics) and F-39 (SSE handlers — dead code vs missing wiring).

## 8. Limitations

Single host class (Linux x86-64) for dynamic checks; Windows/macOS behavior verified only via CI's documented assertions and static bridge analysis. The emulator-based CT spot-check (step-trace variance) was designed but not executed — binary-level CT verification remains a Phase-2 exit item for the Resolution Plan. No formal verification was performed (out of budget by charter). Comment-truth sampling covered 8 claims; the corpus is ~73,200 lines.

## 9. Inputs to the Resolution Plan

The Phase 8 artifact consumes: the register in §3 (with waves pre-assigned), the invariant gate (§7), the scorecard (§6), and the roadmap's wave framework (§8 of `AUDIT-ROADMAP.md`). Every step in the plan is test-first: no fix lands without a failing check that it makes pass.

---

*Phase 7 complete. Phase 8 (Resolution Plan) follows in `resolution-plan.md`. The repository was not modified at any point in this session.*
