# Sovren Audit — Session Log: Phase 2 (Security) & Phase 3 (Performance), with Phase 4/5 previews

| | |
|---|---|
| **Session** | Audit of `discorddioxin/sovren`, per `docs/AUDIT-ROADMAP.md` — continuation of `findings-phase0-phase1.md` |
| **Freeze commit** | `003149e12777f19a3da2433066ddf3f1303da147` (unchanged; Phase 0 baselines remain valid) |
| **Environment** | Linux 6.1.158+ x86-64 (e2b sandbox), 2026-10-18; working copy `/tmp/sovren-audit` (repo + the CI-documented `chmod +x` step, F-03) |
| **Ground-rule compliance** | Read-only on the repo. All mutations, mutant compilers, and reproducers lived in `/tmp` and were restored/verified by `diff -q` against the repo (clean). `git status` in `/home/user/sovren` shows only the new `docs/` files. |
| **Determinism re-check** | The 551-check battery was run twice more this session (under both mutation pilots) and stayed 551/0 — a reproducibility datum in itself [I7]. |
| **Citation rule** | Every claim cites a repository location (`file:line`) or an external authority (CWE / RFC / NIST / OWASP / Intel), listed in §5. |

---

## 1. New findings

| ID | Sev | Component | Title | Design intent? | Invariant |
|---|---|---|---|---|---|
| F-21 | P1 | library/aes.sov | AES SubBytes is a secret-indexed table lookup — variable-time by the standard discipline | accidental (no CT claim anywhere) | I5 |
| F-22 | P1 | library/bigint.sov + tls.sov | Bigint reduction branches on secret data (loop counts, comparisons) in the TLS RSA path | accidental | I5 |
| F-23 | P2 | library/gcm.sov | No atomic verify-then-decrypt: tag comparison is the caller's job (footgun; two callers do it right) | accidental | — |
| F-24 | P2 | library/tls.sov | TLS session keys and ephemeral material are never wiped; they live in the heap until exit | accidental | I5, I6 |
| F-25 | P2 | library/cffi.sov | ELF-only FFI compiles on every target, header says nothing about platform | accidental | I3, I5 |
| F-26 | Info+ | toolchain | Privacy board **independently re-derived and confirmed**: capability-free output, NX holds, prctl emission verified | — | I6 ✓ |
| F-27 | P1 | LICENSE | PSVL §3.3 requires good-faith security research to be disclosed **privately to the Author first** — the Resolution Plan must route security findings accordingly | n/a (legal) | — |
| F-28 | P2 | compilers | Super-linear compile time in **program size** (independent of nesting): 50k statements → 8.1 s | accidental | — |
| F-29 | P3 | tests + cx86.sov | The CI recursion benchmark is constant-folded at compile time; runtime recursion is never measured; the fast path is keyed on source-text shape | deliberate | I5 |
| F-30 | P3 | library/string.sov | `str_cat` in a loop is O(n²) (20k concats = 738 ms); `buf.sov` exists but nothing points users to it | deliberate (documented cost model) | I5 |
| F-31 | Info+ | runtime | Positive: tight-loop and fib performance are excellent (see §3) | — | — |
| F-32 | P2 | tests | **60 of 168 libraries (36%) have zero behavioral coverage** — proven by mutation pilot M1 | accidental | — |
| F-33 | P3 | library | Mutual `use` cycles exist (tls↔web confirmed); name-based resolution tolerates them | accidental | I3 |
| F-34 | Info+ | compilers | Shared-core "verbatim" claim structurally verified: all x86 back ends `use cx86`, zero task collisions | — | I3 ✓ |
| F-35 | P1 | tests | **Mutation pilot: 2/2 mutants survived the 551-check battery**, including a compiler-core mutant proven to miscompile legal programs | accidental | — |

### F-21 — P1 · AES is a secret-indexed table lookup (variable-time)

**Evidence:** `library/aes.sov:96-103` builds the S-box at runtime (good — no embedded table), but `:109` returns `peek_byte(ae_sbox, b)` where `b` is a state byte — a **memory access at a secret-dependent address**, the canonical cache-timing pattern. No crypto library in the tree states a constant-time claim (headers scanned: aes, gcm, chacha20, chachapoly, poly1305, sha256, x25519, bigint, hmac — all silent). [Intel, *Guidelines for Mitigating Timing Side Channels*: access patterns must be independent of secret values; CWE-208.]

**Impact:** a local attacker measuring cache timing can recover AES key material in multi-tenant settings. Likelihood is moderate-low, impact high → P1 per roadmap §7.

**Suggested fix:** bitslice the SubBytes (or document the limitation plainly per I5, as `tls.sov:2` does for certification). **Acceptance:** a source-level CT inventory classifies every crypto path; the AES hot loop has no secret-indexed lookup. **Wave 2.**

### F-22 — P1 · Bigint reduction branches on secret data in the TLS RSA path

**Evidence:** `library/bigint.sov:32-40` (`bi_trim`) loops while trailing limbs are zero — the **loop count depends on the value**; `:97-110` (`bi_cmp`) branches on digit comparisons. The TLS client calls `bi_modpow17(mb, ev, n)` at `library/tls.sov:151-159` with `mb` = the **secret premaster** (base), public exponent, public modulus. Reduction and comparison inside the modpow therefore branch on secret-dependent magnitudes. [CWE-208; Intel CT guidance; the constant-time discipline of HACL* — secret-independent control flow.]

**Mitigating context:** the exponent is public (65537), so this is not the classic square-and-multiply leak; the exposure is the secret *base* during reduction. Also, today the premaster is constant (F-01), which paradoxically removes the variance — **F-01's fix makes F-22 live**, so F-22 must land with or before F-01's fix.

**Suggested fix:** fixed-width limb normalization (no trim on secret values), constant-time comparison in the reduction path, then binary-level verification (emulator step-trace variance across two different premasters — the roadmap's Phase 2 method). **Wave 2, sequenced with F-01.**

### F-23 — P2 · GCM offers no atomic verify-then-decrypt

**Evidence:** `library/gcm.sov` exposes only tag *production* (`gm_finish:209`, `gm_tag_out:167`) — no decrypt-and-verify job. Callers must remember `ct_eq`: `vault.sov:121` does it correctly, and `chachapoly.sov:114` verifies internally ("verifies with ct_eq before decrypting", `:12`) — the good pattern exists in-tree but GCM, the most-used primitive, does not enforce it. [CWE-347 Improper Verification of Cryptographic Signature.]

**Suggested fix:** add `gm_dec_verify` that refuses to return plaintext on tag mismatch, mirroring chachapoly. **Wave 2.**

### F-24 — P2 · TLS key material is never wiped

**Evidence:** `library/tls.sov` does not `use secret` at all (grep: no wipe/secret references), so the ephemeral private key (`ep`), premaster (`pm`), master secret (`ms`), and record keys (`sk`, `rk`) — all heap buffers — persist until process death. `runtime.sov`'s allocator never frees, and `library/secret.sov:4-9` documents exactly this residue class. Contrast `vault.sov:70-72`, which wipes key, blob, and ciphertext. [CWE-316 Cleartext Storage of Sensitive Information in Memory.]

**Suggested fix:** wipe the handshake buffers at the end of `tl_client` (and declare the job `private`, which also arms the dumpable-off path — `secret.sov:14-17`). **Wave 2.**

### F-25 — P2 · cffi is ELF-only, compiles everywhere, says nothing

**Evidence:** `library/cffi.sov:53` — "Map the whole file, then map each **ELF** LOAD segment"; the example path is a Linux `.so` (`:10`). The loader mechanism cannot work on PE/Mach-O, yet `use cffi` builds on all six targets (CI's every-library check proves compilation only). Same class as F-10; joins its fix (header platform labels + compiler warning for unmapped syscalls). **Wave 2.**

### F-26 — Info+ · Privacy board independently re-derived and confirmed

The roadmap required independent verification of pass 115's claims. All four held on this host:
- **No network/process/clock syscall encodings** in a plain compiled binary (scanner over `mov rax,imm` + `0f 05` pairs, numbers 41–56, 227, 230 → 0 hits; matches `suite.sov:2152-2154`).
- **No build metadata**: no paths, hostnames, or toolchain strings in the output binary (regex scan of printable runs → none; matches `suite.sov:2157-2159`).
- **prctl(PR_SET_DUMPABLE, 0) is emitted iff `private`/`wipe` is present**: exactly one `mov eax,157` encoding in the private build, zero in the plain build (binary scan; mechanism at `compilers/linux/compiler.sov:1290-1296`, `emit_nodump`).
- **NX holds**: PT_GNU_STACK parses as `R W` (no X) in both builds (ELF phdr parse; matches the pass S1/S2 comment, `compilers/linux/compiler.sov:44-50`).

### F-27 — P1 · License constrains disclosure of security findings

**Evidence:** `LICENSE` §3.3 — "GOOD-FAITH SECURITY RESEARCH is allowed locally, with **private disclosure to the Author first**" (summary at `LICENSE:99-100`; the audit grant itself is at `LICENSE:29-30`). The findings with security impact (F-01, F-02, F-05, F-06, F-21, F-22, F-24) must therefore be routed privately to the Author before any public publication, and the Resolution Plan must say so. (This session's outputs are private workspace documents, within the grant.)

### F-28 — P2 · Super-linear compile time in program size

**Evidence (live, identical statement shape, varying count):** 1,000 statements → 10 ms; 10,000 → 391 ms (×39); 50,000 → 8,092 ms (×20.7 for ×5 size ≈ O(n^1.9)). Together with F-09 (nesting depth, O(n²)), the compiler has at least two independent super-linear curves. Candidate cause: linear scans over growing lists in the pass pipeline (e.g., the resolver's `idx` linear scan, `library/cx86.sov:5553-5560`). [CWE-400.]

**Suggested fix:** instrument pass timings (the `tr_time` pattern from `library/testrun.sov:24-40` applied to compiler passes), then fix the quadratic structures; add a depth limit and a size-advisory. **Wave 1.**

### F-29 — P3 · The CI recursion benchmark measures the optimizer, not recursion

**Evidence:** `check.yml`'s language check compiles `fib(20)` as a literal; `library/cx86.sov:4993-5021` recognizes that exact shape (`fiblike`) and, per the comment at `:5017-5021`, **computes fib of a compile-time constant iteratively at compile time** — so the CI "recursion" check exercises neither runtime recursion nor the runtime overflow trap. Live proof: `fib(n)` with `n` from `argv` (unfoldable) still completes fib(30) in 1 ms because the recognized shape compiles to an iterative runtime loop (correct output 832040). The fast path is also keyed on **source text**: a semantically identical `if 2 > n` form does not match.

**Suggested fix:** add a runtime-argument recursion benchmark (n from argv) to `tests/bench.sov` or CI; document the shape-matched optimization in the compiler header. **Wave 2.**

### F-30 — P3 · Quadratic string building is undocumented

**Evidence (live):** 20,000 single-character `str_cat` concatenations = 738 ms — each `_sov_strcat` (`runtime.sov`, `_sov_strcat`) allocates and copies the whole string. `library/buf.sov` exists for the streaming pattern, but `string.sov`'s header does not point users to it. [I5: the cost model is real, the guidance is missing.] **Suggested fix:** one header line naming the pattern and the alternative. **Wave 3.**

### F-32 — P2 · 60 of 168 libraries (36%) have zero behavioral coverage

**Evidence:** use-graph extraction over all 328 files: 60 library names are never `use`d anywhere — `array, assert, bench, block, bmp, buf, chachapoly, check, cmp, color, count, date, deque, dict, dm, draw, dump, face, feed, filter, flag, glob, hash, heap, invite, ipaddr, like, line, log, match, matrix, mmio, msg, notify, os, pass, path, perm, port, presence, profile, queue, range, rate, report, room, search, session, set, stamp, stats, term, test, toml, trie, tsv, uid, urlenc, user, wrap`. Their only coverage is CI's "every library builds" step (`check.yml`), which proves compilation, not behavior. **Mutation pilot M1 proves the gap empirically** (F-35).

**Suggested fix:** behavioral checks for the 60, prioritized by user-facing-ness (dict, toml, tsv, csv, uid, perm, date, stats first); the suite's own walk machinery (`suite.sov`, `tr_every_lib_checks`) can be extended from build-only to build-and-run. **Wave 2.**

### F-33 — P3 · Mutual `use` cycles (tls ↔ web)

**Evidence:** `library/tls.sov:29` (`use web`) and `library/web.sov:21` (`use tls`) — a genuine mutual cycle; the reachability scan flags 36 libraries reachable from a cycle. Name-based, order-independent resolution (the compiler resolves `use` at compile time) tolerates it, but the TLS client and the HTTP layer are now coupled: neither can be understood, tested, or replaced alone.

**Suggested fix:** extract the DNS/socket helper (`web_lookup`, `web.sov:170-176`) into a leaf library both can use. **Wave 3.**

### F-34 — Info+ · Shared-core architecture verified

All three x86 back ends `use cx86` (`compilers/{linux,windows,macos}/compiler.sov`), and a task-name collision scan between `cx86.sov` and each per-target compiler finds **zero overlaps** — the "pulled verbatim" claim (`cx86.sov:1-4`) is structurally sound. Same pattern holds for `carm.sov` on the arm64 back ends.

### F-35 — P1 · Mutation pilot: 2/2 mutants survived the battery

**Method** (in the `/tmp` copy, per the roadmap's in-Sovren tooling constraint I8): introduce a semantic mutant, rebuild what depends on it, run the full 551-check battery, restore and verify by `diff -q`.

- **M1 — library mutant (orphan):** `library/roman.sov:50`, `IX`→`XI` (rom_to(9) becomes wrong). **Result: 551 passed, 0 failed — mutant survived**, because no check anywhere uses `roman` (F-32).
- **M2 — compiler-core mutant:** `library/cx86.sov:5008`, the `fiblike` shape matcher's base case `" < 2"`→`" < 3"`, then the Linux compiler rebuilt from the mutated core and swapped in. **Live-mutant proof:** a legal program `fib n: if n < 3 / return n / …` compiles to **wrong output (fib(5) = 5; correct is 7)**. **Result: 551 passed, 0 failed — mutant survived**, because every fib in the battery uses the standard `< 2` shape, which the mutated matcher no longer matches (it falls back to correct recursive compilation).

**Impact:** the battery's oracles are strong for the shapes they pin (differential hardware vectors, NIST/RFC KATs, byte-identity) but silent on (a) 36% of the library surface and (b) the optimizer's pattern-matching boundaries. Both mutants are in exactly the classes the roadmap's Phase 5 targets (mutation gate, per-board behavioral checks). [AugmentCode mutation-testing guidance; roadmap §6 Phase 5.]

**Suggested fix:** a nightly in-Sovren mutation gate: mutate `.sov` text (operator/constant/shape flips), rebuild the compiler, run the battery, report kill-rate; start with the compiler core and the crypto board. **Wave 2.**

---

## 2. STRIDE threat model summary (Phase 2 deliverable)

| Boundary | Spurious threat | Evidence | Status |
|---|---|---|---|
| `.sov` source → compiler | Tampering (hostile input) | Pass S4 board (`suite.sov:2484+`) — empty/NUL/quote-salad inputs give clean errors; deep nesting *stalls* but does not crash (F-09) | covered, with a time-bound gap |
| Compiler → emitted binary | Tampering (wrong code) | Mutation pilot M2 shows a core mutant can miscompile legal programs undetected (F-35) | **gap** |
| Emitted binary → kernel | Elevation of privilege | Unchecked allocation past the heap ceiling (F-07); unchecked indexing default (design intent I4) | known, by design |
| TLS client → network | Repudiation/information disclosure | F-01, F-02, F-05, F-22, F-24 | **primary risk area** |
| Libraries → foreign code | Tampering | cffi loads arbitrary ELF (`cffi.sov`) — deliberate, capability of the host process | accepted, documented |
| Repo → user | Spoofing | Committed binaries proven byte-fresh by bootstrap (Phase 0); exec-bit defect F-03 | proven fresh |

---

## 3. Phase 3 performance measurements (all live, this session)

| Measurement | Result | Note |
|---|---|---|
| `hello.sov` compile, 7 targets | 2–10 ms each | Phase 0 baseline |
| Compile-time scaling (statements) | 1k→10 ms · 10k→391 ms · 50k→8,092 ms | ≈O(n^1.9) — F-28 |
| Compile-time scaling (nesting depth) | 250→365 ms · 500→2,340 ms · 1k→16,366 ms · 2k→≈60 s | O(n²) — F-09 |
| Tight integer loop (bench.sov, 2.9M iterations, known answer) | **5 ms**, correct (`8129670871667150000`) | native codegen is fast |
| fib(30), runtime argument | **1 ms** (iterative fiblike path; correct 832040) | vs gcc -O2 on the recursive source: 3–4 ms |
| Same guest under the in-language x86 emulator | 5M-iteration loop: **2,320 ms** vs ~1 ms native (≈2000×) | consistent with the CI-documented 2.5M steps/s on the self-build workload (`check.yml` emulator-build step); instruction-mix dependent |
| `str_cat` in a 20k-iteration loop | 738 ms | O(n²) — F-30 |
| Full battery | compile 8.6 s + run 55.3 s | Phase 0 baseline |

---

## 4. Hypotheses register — deltas from this session

- **H5 (crypto unaudited)** → **confirmed, expanded**: F-21, F-22, F-24 join F-01/F-02/F-05/F-06.
- **H11 (no coverage/mutation/benchmark gates)** → **confirmed empirically**: mutation pilot 2/2 survivors (F-35); benchmark gap F-29.
- **H14 (global-state coupling)** → partially informed: mutual `use` cycles confirmed (F-33); full coupling map still due in Phase 4.
- **H18 (privacy invariant)** → **independently verified** (F-26): capability-free output, no metadata, NX, conditional prctl — all re-derived.

## 5. References

**Repository evidence (primary):** `library/aes.sov:96-109`; `library/bigint.sov:32-40, 97-110`; `library/tls.sov:151-159` (+ F-01/F-02/F-05/F-06 locations from the Phase 0–1 log); `library/gcm.sov:167, 209`; `library/chachapoly.sov:12, 114`; `library/vault.sov:121`; `library/secret.sov:4-9, 14-17`; `library/cffi.sov:10, 53`; `library/roman.sov:50`; `library/cx86.sov:4993-5021, 5008, 5553-5560`; `library/web.sov:21, 170-176`; `library/string.sov`; `library/buf.sov`; `library/testrun.sov:24-40`; `runtime.sov` (`_sov_strcat`); `compilers/linux/compiler.sov:1290-1296, 1647`; `LICENSE:29-30, 99-100`; `.github/workflows/check.yml` (recursion check, emulator-build step, every-library step).

**External standards (secondary):** CWE-208 (Observable Timing Discrepancy), CWE-316, CWE-347, CWE-400 (MITRE, https://cwe.mitre.org); Intel, *Guidelines for Mitigating Timing Side Channels Against Cryptographic Implementations* (2022); Blanchet et al., *SoK: Computer-Aided Cryptography* (Oakland 2021); *Breaking Bad: How Compilers Break Constant-Time Implementations* (arXiv:2410.13489); OWASP Password Storage Cheat Sheet; AugmentCode, *Mutation Testing* guides (mutation kill-rate methodology); Chen et al., *A Survey of Compiler Testing* (CSUR 2020); roadmap Appendix D.

---

*Phase 2 and Phase 3 are complete; Phase 4 (architecture) and Phase 5 (testing strategy) are partially executed (use-graph, orphan analysis, shared-core verification, mutation pilot) with the remainder — coupling map, coverage proxy, fuzzer extension design — due in the next session. Phase 6 (DX/docs/CI), Phase 7 (synthesis), and Phase 8 (Resolution Plan) remain. The repository was not modified at any point in this session.*
