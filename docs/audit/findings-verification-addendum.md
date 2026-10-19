# Sovren Audit — Verification Addendum (Phase 7 continuation)

| | |
|---|---|
| **Session** | Audit of `discorddioxin/sovren` — closing the parked items, the Phase 2 CT-inventory exit criterion, and the adversarial re-verification pass |
| **Freeze commit** | `003149e12777f19a3da2433066ddf3f1303da147` (unchanged) |
| **Environment** | Linux 6.1.158+ x86-64 (e2b sandbox), 2026-10-18; working copy `/tmp/sovren-audit` |
| **Ground rule held** | Read-only on the repo; all reproducers in `/tmp`; `git status` clean of tracked changes |

This addendum executes what earlier phases explicitly parked: the complete constant-time inventory (Phase 2's exit criterion), the allocator time-to-OOM measurement (Phase 3), the mechanical `mem.sov` universal-builtin sweep (Phase 4), the register-allocation spot check (Phase 3), and the adversarial re-verification of every P0/P1 (roadmap §4). It closes with five new findings (F-56…F-60), two of them P1.

---

## 1. New findings

| ID | Sev | Component | Title | Design intent? | Invariant |
|---|---|---|---|---|---|
| F-56 | **P1** | library/x25519.sov | The X25519 ladder's conditional swap **branches on a secret-derived value** — scalar bits leak through timing | accidental (comment mis-justifies it) | I5 |
| F-57 | P2 | runtime.sov | The documented 64 MB heap ceiling is enforced **nowhere**: 200 MB allocated and written successfully; behavior is host-layout-dependent | accidental | I5 |
| F-58 | **P1** | rand.sov + windows compiler | **Silent zero entropy on Windows**: `getrandom` (318) is not in the Windows bridge; `rand_bytes` never checks the return — vault salts/nonces and tokens become all-zero | accidental | I5, I3 |
| F-59 | P2 | tests | The vault/auth/token boards assert round-trips but never entropy — the oracle gap that let F-58 survive Windows CI | accidental | — |
| F-60 | P2 | library | Complete `mem.sov`-rule sweep: 29 libraries use raw `sys_*` wrappers; the platform-specific set needs the F-10/F-25 labels | accidental | I3 |

### F-56 — P1 · Secret-dependent branch in the X25519 ladder

**Evidence:** `library/x25519.sov:286-298` — `x_cswap sw a b` swaps its arguments **inside `if sw is 1`**, a branch on `sw`. The ladder calls it with `sw` toggled from the scalar's bits: `:437-446` extracts `bit: xx_shr(peek_byte(sb, t / 8), t % 8) % 2` from the secret scalar and sets `sw` from it; `:447-448` call `x_cswap(sw, x2, x3)` and `x_cswap(sw, z2, z3)`. The swap's timing therefore depends on the private key's bits — the classic ladder leak [CWE-208; Intel CT guidance: no secret-dependent control flow]. The in-source comment (`:287-288`, "this is a client's own ephemeral key, no secret is shared here") misreads the call graph: the same function serves the ladder, where `sw` is secret-derived; and even at key generation the scalar is secret. **Interaction with F-01:** today the ephemeral key is constant, so the leaked bits are the same every session — after F-01's fix the leak becomes live, so F-56 joins F-22 in the Wave-0 sequence.

**Suggested fix:** mask-based swap, limb-wise over the 10 limbs, using the existing `wand`/`wxor` primitives (as `poly1305.sov`/`gcm.sov` already do): `mask: 0 - sw; t: wand(mask, wxor(a_i, b_i)); a_i: wxor(a_i, t); b_i: wxor(b_i, t)` — no branch, no secret-dependent memory access. **Acceptance:** a suite board runs the ladder under the emulator with two different scalars and asserts indistinguishable step timing (the dudect-style probe the roadmap designed); the `< 3`-shape mutant class from F-35 stays caught. **Wave 0** (with F-01/F-22).

### F-57 — P2 · The 64 MB ceiling is fictional in practice

**Evidence (live):** a program allocating 200 × 1 MB chunks and poking each chunk's last byte ran to completion — "200 MB allocated without failure", exit 0. The runtime maps 64 MB (`runtime.sov:17-20`, `syscall(9, 0, 67108864, …)`, `heap_end: heap_ptr + 67108864`), but `_sov_alloc` (`runtime.sov:43-50`) is a pure bump: `p: heap_ptr; heap_ptr: heap_ptr + n` — **`heap_end` is never consulted** (F-07's root cause). Over-allocation therefore walks past the mapping into whatever the kernel placed next: on this host, 136 MB of writable address space; on another, SIGSEGV. The documented ceiling is neither checked nor enforced — behavior is host-layout-dependent, the worst class [CWE-782 reliance on undefined layout]. This also resolves H4's open question: time-to-OOM is unmeasurable because there is no OOM.

**Suggested fix:** check `heap_ptr + size > heap_end` and trap cleanly through the runtime's named-trap path (the div-by-zero/overflow discipline, Phase 1) — never a silent walk. **Acceptance:** the 200-chunk reproducer traps with a named reason at chunk 64; a suite board pins it. **Wave 2.**

### F-58 — P1 · Silent zero entropy on Windows

**Evidence (complete static trace):**
1. `library/rand.sov:5-7` — `rand_bytes` calls `sys_getrandom(buf, n)` and **never checks its return**; the buffer is returned as-is.
2. `library/sys.sov:74-76` — `sys_getrandom` is raw `syscall(318, …)`.
3. `compilers/windows/compiler.sov:1643-1724` — the `_sov_wincall` bridge maps only syscall numbers **{0, 1, 2, 3, 8, 9, 16, 60}** (read, write, fork, close, execve, mmap, ioctl, exit); the slim two-branch fast path covers only write/exit (`:1488-1500`). Number 318 matches nothing; the default path returns error sentinel 49 (`:1496-1500`).
4. Therefore on Windows every `rand_bytes` returns an **all-zero buffer, silently**.
5. Consumers: `vault.sov:44-45` (`salt: rand_bytes(16)`, `nonce: rand_bytes(12)`) — zero salt **and** zero nonce means GCM nonce reuse under a password-derived key (the catastrophic class), and deterministic ciphertext for repeated saves; `token.sov:12` — zero session tokens; `auth.sov` (salt path); `fuzzlib.sov`.
6. **Why CI is green anyway:** the vault board (`suite.sov:2744-2752`) asserts round-trips and tamper-rejection — both hold with zero randomness. No check asserts entropy.

**Positive contrast:** the macOS bridge maps 45 syscall numbers **including 318** (`compilers/macos/compiler.sov:1375-1867`) — macOS gets real entropy; only Windows is broken. [CWE-338 use of weak PRNG; CWE-330 insufficient randomness; GCM nonce-reuse, NIST SP 800-38D §8.2.]

**Suggested fix (three parts, all in-Sovren `[I1]`):** (a) `rand_bytes` traps when `sys_getrandom` returns < 0 (I5 honesty — no silent fallback); (b) extend the Windows bridge's mapped set with 318 → `BCryptGenRandom`/`RtlGenRandom` (the `_sov_wincall` dispatcher pattern already exists); (c) add the differential-randomness suite board (F-59). **Acceptance:** on a Windows runner, two `vault_save` calls with identical plaintext+password produce different ciphertexts; the rand board fails pre-fix and passes post-fix. **Wave 1** for (a)+(c), **Wave 2** for (b).

### F-59 — P2 · Entropy is never asserted anywhere

**Evidence:** the vault/auth/token boards (`suite.sov:2744-2775`) check round-trips, wrong-password rejection, and tamper detection — all of which pass with zero randomness. No check draws two samples and compares them. This is the oracle gap that made F-58 invisible on Windows CI. [Testing literature: oracles must distinguish the property, not just the happy path.] **Suggested fix:** boards for (a) `vault_save` twice with same inputs → ciphertexts differ; (b) 100 `token_new` draws → 100 distinct values; (c) the same for `auth` salts. **Wave 2** (lands with F-58).

### F-60 — P2 · The `mem.sov` universal-builtin rule, swept mechanically

**Evidence:** extraction of every `sys_*(` call site across all 168 libraries: **29 libraries use raw syscall wrappers** — `arm, binfile, bounds, cffi, dir, file, image, key, line, log, os, pipe, proc, rand, run, secret, shell, sock, sys, term, termkit, testrun, time, tool, tui, walk, web, winx11, x86`. The universal set (write/read/mmap/exit/close/ioctl/clock/getrandom) is legitimately shared; the platform-specific users (`dir, os, pipe, proc, run, shell, tool, sock, key, line, term, termkit, tui, winx11, cffi`) extend F-10/F-25's list and all need the platform labels that finding asks for. The sweep table is the mechanical completion of the parked Phase 4 item. **Wave 2** (with F-10/F-25).

---

## 2. Constant-time inventory — Phase 2's exit criterion, closed

Source-level classification of every crypto primitive (secret-dependent branch / secret-indexed access / variable-latency operand), with the hot-path evidence:

| Primitive | Classification | Evidence |
|---|---|---|
| SHA-256 | **CT-clean** | branches only on the public round index (`sha256.sov:26-36`); no tables |
| ChaCha20 | **CT-clean** | single `if` on the public block boundary (`chacha20.sov:85`) |
| Poly1305 | **CT-clean** | limb selection by public counter `limb: i / 26` (`poly1305.sov:54-62`) |
| GCM/ghash | **CT-clean** | branches on public word index and lengths (`gcm.sov:51-118, 299, 329`) |
| HMAC/HKDF/PBKDF2 | **CT-clean** | inherit SHA-256; branches on public key length (`hmac.sov:24-35`) |
| X25519 | **VIOLATION** | `x_cswap` branches on secret-derived `sw` — F-56 |
| bigint | **VIOLATION** | reduction loop counts/comparisons branch on secret magnitudes — F-22 |
| AES | **VIOLATION** | secret-indexed S-box lookup — F-21 |

**Caveat (per the roadmap's method note):** source-level CT does not guarantee binary-level CT — compilers break source-level guarantees ("Breaking Bad", arXiv:2410.13489). The binary-level verification (emulator step-trace variance across two secrets, the dudect-style probe) was **designed but not executed**; it is the mandatory verification step for the F-21/F-22/F-56 fixes in Wave 0/2.

## 3. Adversarial re-verification of every P0/P1

Per roadmap §4, each P0/P1 was re-derived by an independent route:

| Finding | Independent re-derivation | Verdict |
|---|---|---|
| F-01 (P0) | Source arithmetic re-read (`tls.sov:554-560`, `:336-340`); two live ClientHello captures byte-identical (Phase 1) | **Stands** |
| F-02 (P1) | DER walker re-read (`tls.sov:523-539` — modulus/exponent only); live self-signed/wrong-host fetch succeeded | **Stands** |
| F-03/F-48 (P1) | Fresh `git clone` this session: first command fails; fix is the CI-only chmod ritual | **Stands** |
| F-04 (P1) | Suite inventory: none of the 39 check groups exercises `tl_get`/`tl_send` end-to-end | **Stands** |
| F-05 (P1) | Live github.com fetch: only the curl fallback produced output; no in-language TLS debug prints | **Stands** |
| F-21 (P1) | `aes.sov:109` re-read: `peek_byte(ae_sbox, b)`, `b` a state byte | **Stands** |
| F-22 (P1) | `bigint.sov:32-40` (`bi_trim` loop on value), `:97-110` (`bi_cmp`), called on the secret premaster at `tls.sov:151-159` | **Stands** |
| F-27 (P1) | `LICENSE:99-100` read directly | **Stands** |
| F-35 (P1) | Both mutants re-run this session; M2 proven live (legal program → wrong answer 5 ≠ 7) before the suite was declared green | **Stands** |
| F-56 (P1) | Ladder re-read end-to-end (`:427-448`); the secret path is unambiguous | **Stands** (new) |
| F-58 (P1) | Full static chain re-walked: `rand.sov:5-7` → `sys.sov:74` → bridge tables (Windows `{0,1,2,3,8,9,16,60}` vs macOS 45 incl. 318) → consumers `vault.sov:44-45`, `token.sov:12` | **Stands statically; dynamic Windows verification owed** (the acceptance test in F-58 defines it) |

## 4. Parked items — closure

| Parked item | Outcome |
|---|---|
| REPL per-line latency | **Closed**: 5 ms/line measured (F-51) |
| Allocator time-to-OOM at the 64 MB ceiling | **Closed**: no OOM exists — ceiling unenforced, 200 MB writable (F-57) |
| Mechanical `mem.sov` universal-builtin sweep | **Closed**: 29 libraries enumerated (F-60) |
| Register-allocation / codegen quality review | **Partially closed**: source-level review of the emit helpers and the `homereg` spill path found no defect in the spot-checked paths; a full review needs emulator-based instruction-mix profiling — **still open**, recommended as a Wave-3 tooling task |
| Binary-level CT probe (step-trace variance) | **Designed, not executed** — the mandatory verification step for the F-21/F-22/F-56 fixes |

## 5. References

**Repository evidence (primary):** `library/x25519.sov:286-298, 427-448`; `runtime.sov:17-20, 43-50`; `library/rand.sov:1-8`; `library/sys.sov:74-76`; `compilers/windows/compiler.sov:1438-1500, 1643-1724`; `compilers/macos/compiler.sov:1375-1867`; `library/vault.sov:35, 44-45`; `library/token.sov:3, 12`; `library/suite.sov:2744-2775`; `library/{sha256,chacha20,poly1305,gcm,hmac,hkdf,pbkdf2}.sov` (branch sites cited in §2); live OOM reproducer (200×1 MB, exit 0).

**External standards (secondary):** CWE-208, CWE-330, CWE-338, CWE-782 (MITRE, https://cwe.mitre.org); Intel, *Guidelines for Mitigating Timing Side Channels* (2022); NIST SP 800-38D §8.2 (GCM nonce-uniqueness requirement); *Breaking Bad: How Compilers Break Constant-Time Implementations* (arXiv:2410.13489); roadmap §4 (adversarial validation rule).

---

*Register now stands at 51 findings (1×P0, 11×P1, 24×P2, 15×P3) plus 8 verified positives. The repository was not modified at any point in this session.*
