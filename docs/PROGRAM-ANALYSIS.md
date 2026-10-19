# Sovren — Program Analysis: Purpose, Semantics, and Purpose-Impact Assessment of the Audit Roadmap

| | |
|---|---|
| **Purpose of this document** | Understand what Sovren *is for* and how it *means what it says*, then verify that `docs/AUDIT-ROADMAP.md` cannot damage either. Every claim below is cited to source. |
| **Method** | Full read of the bootstrap chain, runtime, launcher, REPL, debugger, compiler headers/pass markers, the test battery's organizational comments, and the headers of the standard library (all 168 files inventoried; ~40 read in full). |
| **Ground rule preserved** | Analysis only. No repository files were read-modified; the roadmap is amended by separate, clearly-marked edits. |

---

## 1. What Sovren is *for* (purpose, from evidence)

Sovren is a **self-contained, self-hosting systems programming language**. Its purpose, as stated across the source, has seven strands:

1. **Native compilation with nothing installed.** `launcher.sov` prints *"sovren — native x86-64, self-contained"*. One source file compiles to a real ELF/PE/Mach-O binary for six targets (Linux, Windows, macOS, Android, iOS, bare metal) with no linker, no libc, no toolkit: *"syscall is the only builtin. The compiler turns `syscall` into the one x86-64 `syscall` instruction. Everything else is Sovren."* (`runtime.sov:1-2`).
2. **The toolchain is written in itself, provably.** `bootstrap.sov` rebuilds all ten committed artifacts from the 10 KB seed and byte-compares them, and re-proves the self-host fixed point (g3 == g4 == g5). The repo's stated contract: *"source + one 211 KB seed = everything else."*
3. **Demonstration and learning.** The license grants use for *"evaluation, security auditing, performance research, learning the language"*. Comments teach design reasoning, not just code: *"The protocol is a stream of little request packets and reply packets, and that is all a window ever was."* (`winx11.sov`).
4. **Honesty about limits.** A stated ethic: the emulator *"is deliberately strict"* (`x86.sov:16`); the REPL's cost is *"the honest price of a language with no interpreter"* (`repl.sov:13`); Discord lacks websockets so it polls *"the way a simpler bot does"* and says so (`discord.sov`); TLS is *"Batteries, not certified: review before production crypto"* (`tls.sov:2`); C stubs are *"stubs, on purpose"* (`cffi.sov:24`).
5. **Privacy and capability discipline, enforced not promised.** The suite's *privacy board* (pass 115, `suite.sov:1928+`): emitted binaries carry *"no capability and no metadata that the source did not ask for"* — no network-syscall encodings in plain output, no build-machine metadata, bit-identical rebuilds, and **the compiler source itself contains no network, process, or clock syscalls** (`suite.sov:2177`).
6. **Performance by default, safety opt-in.** *"every read and write in the language is unchecked… that is the right default for a language with no collector and no runtime to pay for the check, and the wrong default while a program is being written"* (`bounds.sov:4-8`).
7. **One source, every machine.** Per-OS differences are isolated to syscall tables, image writers, and entry conventions; shared cores (`cx86.sov`, `carm.sov`) are *"pulled verbatim"* from the back ends. A hard architecture rule is stated in `mem.sov`: *"a shared library may only use a builtin that every target has."*

**Purpose statement (synthesis):** *Sovren exists to prove — and to let users practice — that a complete, dependency-free native toolchain can be written in its own language, run everywhere from bare metal to phones to desktops, stay honest about its limits, and default to privacy and speed, with safety features available when a program has not yet earned its speed.*

---

## 2. Semantics (how the program means what it says)

### 2.1 Value model
- **One word, two kinds.** Every value is a 64-bit word: small integers are immediates; anything ≥ 4096 is treated as a heap pointer (`_sov_strlen` guard, `runtime.sov`). There are **no types** (*"There are no types in Sovren"*, `json.sov`).
- **Printing is a heuristic, by design**: a word whose first byte is printable ASCII with plausible length prints as text, else as an integer (`_sov_print_val`). A small number and a one-letter text compare equal (`_sov_txt_eq`: *"letters equal letters"*).
- **Text** = NUL-terminated heap bytes. **Lists** = `[cap, len, items…]` with doubling growth. **Buffers** = `[cap, len, bytes…]`.

### 2.2 Language surface
- Indentation blocks; `main:` entry; **jobs** (functions) with `return`; `stop` exits; `if` / `if not` / `as long as` / `… times`; **exceptions** via `raise` / `try` / `except` with a printed trace (suite: *"try raise in call"*).
- `use <name>` resolves a library relative to the compiler (`compilers/linux/compiler.sov:2505`).
- Jobs are first-class: `addr_of` + `cfunc` call through the C convention, and *"addr_of and cfunc must exist on every machine"* (suite gate).
- Keywords `wipe` and `private` change security behavior: the compiler emits `prctl(PR_SET_DUMPABLE, 0)` and wipes private frames on exit (passes 117/118, `vault.sov` header).

### 2.3 Memory & concurrency
- **Heap**: one 64 MB anonymous `mmap`; **bump allocator, never freed**; an atomic spinlock makes the bump thread-safe (`_sov_alloc`). Arenas (`arena.sov`) give mark/end batch release — the sanctioned way to "free".
- **Indexing is unchecked by default**; `bounds.sov` provides opt-in checks that *name the index and length that disagreed* and stop the program. `mmio.sov` is raw, unchecked, *"Unsafe by design"* for device registers.
- **Tasks**: `spawn(job, up to 6 args)` / `join(handle)`. Linux uses `clone` (CLONE_VM…) with a **fork fallback** when clone is refused (sandboxes); Windows/macOS use CreateThread/`vm_allocate` behind a common control-block bridge. Results travel through a shared 64 K slot pool (8,000 slots); wakeups are futex-based. The suite wraps every concurrency check in a timeout because *"a lost wakeup would hang the whole battery"*.

### 2.4 Security & privacy semantics
- Stack canaries seeded from OS entropy per platform (pass S5: advapi32 on Windows, getentropy on macOS); crash handlers that wipe private frames (pass S6); NX stack via PT_GNU_STACK (passes S1/S2); PIE everywhere (pass S7: Linux PIE, Windows PIE with loader-applied `.reloc`); emulator memory carries real page permissions (pass S8).
- **Privacy invariant (pass 115)** as listed above — the compiler itself is capability-free.

### 2.5 Error & diagnostics semantics
- Jobs return `0`/negative on failure; diagnostics are text probed with `str_has(msg, "Error")`. Errors name the file and line (`err_line`, `src_name`). The compiler must *"answer hostile input with a clean error"* (pass S4: empty, NUL bytes, bare quotes, CRLF, tabs, `use spam`, keyword salad).

### 2.6 Build & test semantics
- The compiler compiles itself; committed binaries are artifacts proven fresh by `bootstrap.sov`. Tests are Sovren programs compiled by the compiler under test and run — natively, or inside the in-language x86/ARM emulators, or cross-compiled to PE/Mach-O and executed *inside the emulator* with byte-identity checks against native builds.

**Known drift found during this analysis (an existence proof for the roadmap's comment-truth check):** `runtime.sov`'s spawn comment says *"a spawned job must not allocate from the heap yet - the bump pointer is not thread-safe"*, but `_sov_alloc` has carried an atomic spinlock since it was written. The **code** is thread-safe; the **comment** is stale. This is comment drift, not a concurrency bug — exactly the distinction the audit must get right.

---

## 3. Design invariants (the purpose-protectors)

These are deliberate, source-documented decisions. The audit must treat them as **constraints on its own recommendations**, not as defects:

| # | Invariant | Evidence |
|---|---|---|
| **I1** | **Self-containment**: no external build or run dependencies; the syscall bridge is the only builtin | `runtime.sov:1-2`; `mem.sov` rule; `cffi.sov` is opt-in and labeled |
| **I2** | **Self-hosting with reproducibility proofs**: seed + byte-identical rebuilds + fixed point | `bootstrap.sov`; CI *self host, byte for byte, three times* |
| **I3** | **One source, six targets**: per-OS divergence confined to syscall tables, image writers, entry conventions; shared cores byte-identical; shared libraries use only universal builtins | `carm.sov`/`cx86.sov` headers; `mem.sov` |
| **I4** | **Speed by default**: unchecked indexing, no GC, no runtime checks in the default path; safety is opt-in and paid only when chosen | `bounds.sov:4-8`; `mmio.sov` |
| **I5** | **Honesty**: strict emulation, plain errors, no silent fallbacks, limits documented in place | `x86.sov:16`; `web.sov`; `discord.sov`; `repl.sov:13` |
| **I6** | **Privacy/capability discipline**: no hidden capabilities, no build metadata, capability-free compiler, bit-identical rebuilds | suite pass 115 (`suite.sov:1928+, 2141-2177`) |
| **I7** | **Determinism**: fixed fuzz seeds, reproducible builds, timing instrumentation opt-in (`tr_time`) | `fuzzlib.sov`; `bootstrap.sov`; `testrun.sov` |
| **I8** | **Dogfooding**: the tests, the debugger, the race detector, the fuzzer, and the emulators are all Sovren programs | `suite.sov`, `tools/debug.sov`, `race.sov`, `fuzzlib.sov` |

---

## 4. Purpose-impact assessment of the audit roadmap

Verdict per phase: **SAFE** (aligned as written), **AMEND** (would risk harm as written), with the specific amendments.

| Phase | Verdict | Analysis |
|---|---|---|
| 0 Baseline | SAFE | Freezing, bootstrap reproduction, baselines — all align with I2/I6. |
| 1 Correctness | **AMEND** | Unchecked indexing must not be filed as a bug — it is I4. Only *accidental* harm (a library that silently corrupts where a check was promised) is a finding. The stale spawn comment must be filed as comment drift, not a race. |
| 2 Security | **AMEND** | (a) Crypto remediation must be **in-language** — "replace with OpenSSL/libgcrypt" violates I1/I3. (b) SHA-1 is present for learning/compat; the finding is "deprecated primitive reachable by default", fix = documentation/warning, not removal. (c) TLS certificate-validation completeness is legitimate *only because* `tls.sov` claims to walk the DER — a gap between claim and behavior is a bug under I5. (d) Seed provenance: recommend documentation + emulator-based behavioral verification, **not** "rebuild the seed" (there is no C source; the seed is the axiom). (e) The privacy board's "compiler source has no network/process/clock syscall" is an invariant to *verify*, and recommendations must never add such capabilities (no telemetry, no version phone-home). |
| 3 Performance | **AMEND** | Must not recommend GC, mandatory bounds checks, or any default-path cost — that is I4. The allocator's never-free design is deliberate; the sanctioned remedy is arenas (`arena.sov`), not a collector. REPL latency is documented honesty (I5): measure and document, do not redesign. |
| 4 Architecture | **AMEND** | (a) Decomposition of `suite.sov`/`cx86.sov` is optional and must preserve the *"one list of checks"* property and the no-build-system model (splitting via additional `use` files is allowed; introducing a build step is not). (b) Compiler-pass globals are intrinsic to the single-pass, no-types design — assess and document the cost; do not mandate restructuring. (c) The string-based error model is deliberate (no types); structured errors would be a language redesign — file as a *design proposal*, never a bug. (d) Verify the `mem.sov` universal-builtin rule and the `cx86.sov:5555` naming rule (*"a shorter name must never win over a longer"*) as architecture constraints. |
| 5 Testing | **AMEND** | (a) All tooling recommendations must be **in-Sovren** (I8): extend `fuzzlib.sov` rather than importing libFuzzer/AFL; coverage feedback via the emulator's step trace; mutation testing by mutating `.sov` text and recompiling. (b) Fixed fuzz seeds are deliberate (I7, reproducibility): recommend a *persisted corpus + optional per-run seed*, keeping the fixed seed as the regression default. (c) There is already a unit layer — `assert.sov`, `test.sov` — and the compile-run-compare model *is* the unit model; do not import a foreign framework. (d) Keep the real-hardware CI philosophy (I1/I5); recommend isolation fixes (`mktemp`) and deterministic synchronization, which align with I7. |
| 6 DX/Docs/CI | **AMEND** | README and SECURITY policy are safe and valuable. Do **not** recommend relicensing (PSVL is deliberate) or a package manager (violates I1). Workflow SHA-pinning is safe (CI-only). Recommend documenting the invariants (Section 3) themselves. |
| 7–8 Synthesis & Resolution Plan | **AMEND** | Waves must carry an **invariant-preservation gate**: no step may violate I1–I8 without an explicit design-decision record. |

**Net effect:** the roadmap's *shape* (phases, severity, waves) is sound; its *recommendation vocabulary* needs a constraint layer so that "fixes" cannot quietly trade away the properties that make Sovren Sovren.

---

## 5. Amendments applied to the roadmap

The following edits were made to `docs/AUDIT-ROADMAP.md` as a result of this analysis:

1. New **§4.1 Purpose-protecting invariants** (I1–I8) with a standing rule: *a finding against a deliberate, documented decision is a design proposal, not a bug, and requires a design-decision record.*
2. **Findings schema** gains two fields: `Design intent?` (deliberate / accidental / unknown) and `Invariant touched` (I1–I8 / none).
3. Phase 1: unchecked-indexing and spawn-comment items reframed.
4. Phase 2: crypto remediation constrained to in-language fixes; SHA-1 reframed; seed provenance reframed; privacy-invariant verification added (compiler capability-free check).
5. Phase 3: no-default-path-cost rule; arenas-not-GC; REPL honesty.
6. Phase 4: decomposition constraints; globals assessment (not restructuring); error model as design proposal; `mem.sov` rule verification.
7. Phase 5: in-Sovren tooling constraint; fuzz-seed framing; existing unit layer acknowledged; real-hardware CI preserved.
8. Phase 6: no relicensing, no package manager; document-the-invariants added.
9. Resolution waves: invariant-preservation gate added to every wave; bounds item reframed as policy documentation; TCB item reframed as provenance + emulator verification; fuzz item reframed as `fuzzlib` extension with fixed-seed default.
10. Hypotheses register gains **H17** (comment/code drift class, with the spawn comment as the confirmed first instance) and **H18** (privacy invariant: verify the compiler source is capability-free and that no recommendation can add a capability).

---

## 6. Residual risks to purpose (accepted, monitored)

- **Audit gravity**: even a well-formed audit can bias a project toward "fix the findings" at the expense of the design's soul. Mitigation: the design-intent register makes deliberate choices visible so triage debates them explicitly rather than silently reversing them.
- **Recommendation drift**: a future reader may apply the Resolution Plan without reading the invariants. Mitigation: the invariant gate is attached to each wave, not just to this document.
- **Emulator-fidelity ceiling**: conclusions drawn inside the in-language emulators are only as good as the emulators; the roadmap already classifies such evidence and extends differential vectors (ARM) rather than trusting fidelity.

*The program's purpose is safe under this audit: the audit now audits **with** the design, not against it.*
