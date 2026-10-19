# Sovren Audit — Session Log: Phase 0 & Phase 1 Findings

| | |
|---|---|
| **Session** | Audit of `discorddioxin/sovren`, per `docs/AUDIT-ROADMAP.md` |
| **Freeze commit** | `003149e12777f19a3da2433066ddf3f1303da147` ("Placeholder", single commit) |
| **Environment** | Linux 6.1.158+ x86-64 (e2b sandbox), 2026-10-18 |
| **Phases executed** | Phase 0 (baseline & freeze), Phase 1 (correctness & defect hunt) |
| **Ground-rule compliance** | Read-only on the repo. All builds, binaries, and reproducers live in `/tmp`; the working copy `/tmp/sovren-audit` mirrors the repo with the CI-documented `chmod +x` step applied (see F-03). `git status` in `/home/user/sovren` shows only the new `docs/` files. |
| **Citation rule** | Every claim cites either a repository location (`file:line`) or an external authority (CWE / RFC / NIST / OWASP), listed in §6. |

---

## 1. Phase 0 — Baseline results

| Baseline | Result | Source |
|---|---|---|
| Bootstrap proof (`bootstrap.sov`) | **clean** — seed fixed point g3==g4==g5, all ten artifacts byte-identical to committed; 26.3 s | `bootstrap.sov:14-23, 40-103`; live run |
| Full battery (`tests/all.sov`) | **551 passed, 0 failed** | live run |
| Battery timing | compile 8.6 s + run 55.3 s ≈ 64 s on this host (the suite's own comment budgets ~105 s on CI hardware, `tests/fast.sov:8-13`) | live run |
| `hello.sov` compile, per target | linux 3 ms / windows 3 ms / mac 2 ms / android 6 ms / ios 10 ms / android-so 4 ms / bare 2 ms — all rc=0 | live runs |
| `hello.sov` binary size | linux 4,240 B · windows 2,076 B · mac 4,248 B · android 4,184 B · ios 4,316 B · android-so 5,108 B · bare 4,240 B | live builds |
| Artifact inventory | 328 files, 5.6 MB; 168 libraries; 110 probe files; ~73,200 lines of `.sov` | `git ls-files`, `wc -l` |
| Fresh-clone usability | **broken on Linux/macOS** — see F-03 | reproduced live |

**Environment note (evidence for F-03):** `./sovren bootstrap.sov` failed in the pristine checkout with `Error: could not start the compiler` because `compilers/linux/compiler` is committed without the executable bit. The audit continued in a `/tmp` copy using the exact `chmod +x` step the project's own Linux CI job uses (`.github/workflows/check.yml:339-344`).

---

## 2. Findings register

Severity per roadmap §7. "Design intent?" and "Invariant" columns per roadmap §4.1.

| ID | Sev | Component | Title | Design intent? | Invariant |
|---|---|---|---|---|---|
| F-01 | **P0** | library/tls.sov | TLS client uses a constant X25519 ephemeral key and a constant ClientHello random — every session is passively decryptable | accidental (comment claims "ephemeral") | I5 |
| F-02 | P1 | library/tls.sov | No certificate validation at all — self-signed, expired, wrong-hostname certs accepted (proven live) | accidental? disclaimer is generic | I5 |
| F-03 | P1 | repo modes / launcher | Fresh clones cannot compile anything on Linux/macOS: committed binaries are non-executable | accidental | — |
| F-04 | P1 | tests | Zero end-to-end TLS coverage anywhere in the battery | accidental | — |
| F-05 | P1 | library/tls.sov, web.sov | ClientHello has no extensions (no SNI) → in-language TLS fails on most real hosts, silently masked by a curl fallback | accidental | I1, I5 |
| F-06 | P2 | library/tls.sov | Two stray debug `print`s leak handshake bytes to stdout on every HTTPS call | accidental | I5 |
| F-07 | P2 | runtime.sov | `_sov_alloc` has no heap-ceiling check; over-allocation writes past the 64 MB mapping (observed silent success) | accidental | I5 |
| F-08 | P2 | compiler + runtime | Stack-exhaustion crashes bypass the crash handlers — bare SIGSEGV, no message, private frames not wiped | accidental | I5, I6 |
| F-09 | P2 | compilers | Super-linear (≈quadratic) compile time in expression-nesting depth: 4 KB file stalls the compiler ~60 s | accidental | — |
| F-10 | P2 | 6 libraries | Raw Linux syscall numbers with no Windows/macOS bridge and no platform label on the header | accidental | I3, I5 |
| F-11 | P2 | suite + libraries | Hardcoded `/tmp` paths (311 in suite.sov; fixed temp files in discord.sov/web.sov) — collisions and symlink surface | accidental | — |
| F-12 | P2 | library/vault.sov | No PBKDF2 iteration floor; `iters=1` vaults save and load fine | accidental | — |
| F-13 | P2 | compilers | Most diagnostics lack file:line, though the compiler tracks it (used by arity errors and the debugger) | accidental | I5 |
| F-14 | P3 | compilers | Out-of-range integer literals silently wrap (`99999999999999999999` → `7766279631452241919`) | accidental | I5 |
| F-15 | P3 | library/rand.sov | `rand_below`/`rand_range`: modulo bias (86/85/85 split) and a 256-value ceiling; latent (no internal callers) | accidental | — |
| F-16 | P3 | runtime.sov, bootstrap.sov | Comment drift: stale "must not allocate" spawn comment; "211 KB seed" vs actual 225,144 B | accidental (drift) | I5 |
| F-17 | P3 | compilers | `Warning: locals` is unactionable (no line, no remedy); inconsistent with `Warning: empty` which does print the line | accidental | I5 |
| F-18 | P3 | library/web.sov | Helper stderr leaks to the user's terminal; TLS failures set no reason (`web_why` stays OK) | accidental | I5 |
| F-19 | P2 | library/fuzzlib.sov | Fuzzer: LCG PRNG, fixed seeds, 300 programs, expression-only grammar, no corpus/minimization/coverage feedback | deliberate-but-immature | I7 |
| F-20 | P2 | library/suite.sov | 182 KB test monolith + hardcoded 14-item skip list | deliberate | I1, I3 |

### F-01 — P0 · TLS client: constant ephemeral key and constant client random (complete confidentiality failure)

**Evidence (static):** `library/tls.sov:554-560` — `tl_step_ep` fills the client's X25519 private key with a fixed formula: `poke_byte(ep, i, (i * 13 + 5) % 256)`. `library/tls.sov:336-340` — the ClientHello random is filled with `poke_byte(rcrs, i, i * 7 % 256)`. `grep -c rand library/tls.sov` = 4, **all in comments** — the file never calls the kernel RNG, though `library/rand.sov` provides `rand_bytes` via `getrandom` (`library/rand.sov:4-6`). The code comment at `tls.sov:552-553` calls this "our ephemeral X25519 keypair" — the implementation is the opposite of ephemeral.

**Evidence (live):** two ClientHellos captured from two separate runs of the same program contain byte-identical `client_random`:
`00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9` (visibly the `(i*7)%256` pattern).

**Impact:** the premaster secret is `X25519(ep, spub)` where `ep` is a public source constant and `spub` travels in cleartext in ServerKeyExchange — any passive network observer computes it, then the master secret (both randoms are known: the client random is constant, the server random is on the wire), then every session key. There is no forward secrecy, ever. This is a total break of TLS confidentiality for every `use tls` / `web_get https` / bot-library user. [CWE-330, CWE-338; RFC 5246 §7.4.1.2 requires ClientHello.random to be unpredictable; RFC 7748 §3 requires fresh random scalars for ephemeral keys.]

**Suggested fix (in-Sovren, I1):** `ep: rand_bytes(32)` and the client random from `rand_bytes(32)` — the pattern `vault.sov:31-32` already uses for salt and nonce. **Acceptance:** two connections to the same server yield different client_randoms and different `epu` values; a suite check captures two ClientHellos and asserts inequality. **Wave 0.**

### F-02 — P1 · TLS client accepts any certificate (no validation whatsoever)

**Evidence (static):** `library/tls.sov:523-539` (`tl_step_cert`) checks only that the record is a handshake (type 22), then extracts the RSA modulus/exponent (`tl_cert_key`, `tls.sov:86-99`) to verify the ServerKeyExchange signature. `grep -n "expiry\|expire\|hostname\|issuer\|chain\|verify" library/tls.sov` → zero hits. There is no validity-period check, no hostname match, no chain/CA trust, no revocation.

**Evidence (live):** a local HTTPS server presenting a self-signed certificate (CN=localhost, 2-day validity, connected via IP 127.0.0.1) — the Sovren client completed the handshake and returned the body: output `19 / SECRET-MARKER-12345`. An active MITM can therefore present any certificate and read/write the whole session, including bot tokens (`discord.sov`, `telegram.sov` send tokens over this TLS). [CWE-295 Improper Certificate Validation.]

**Mitigation noted:** the header disclaimer "Batteries, not certified: review before production crypto" (`tls.sov:2`) is generic; it does not state that certificates are not validated at all, so a reasonable user would assume standard TLS semantics [I5 violation].

**Suggested fix:** implement at minimum validity-period + hostname + chain verification against a small trusted-root set, or refuse connections by default with a plain "certificates are not validated" message. **Acceptance:** the live self-signed test above must fail cleanly. **Wave 0** (it is a P0-class gap mitigated only by the disclaimer; rated P1 pending the maintainer's intent decision — see design-intent note).

### F-03 — P1 · Fresh clones cannot compile anything on Linux or macOS

**Evidence:** `git ls-files -s` shows every tool binary committed as mode `100644` — `compilers/{linux,windows,macos,android,ios,android-so}/compiler*`, `sovren-dbg`, `sovren.exe`, `tests/macos-check`, `tests/arm64/check` — while only the `sovren` launcher is `100755`. The launcher `execve`s the per-target compiler (`launcher.sov`, `lc_exec` → `syscall(59, path, argv, …)`), which fails with EACCES. **Reproduced live** in the pristine checkout: `./sovren bootstrap.sov` → `Error: could not start the compiler`.

**Why CI never saw it:** the Linux job runs a mid-workflow "make things runnable" chmod step (`.github/workflows/check.yml:339-344`); the macOS job never invokes the launcher at all (it runs the prebuilt `tests/macos-check` directly, `check.yml:283-310`); Windows ignores the bit (PE loader). The only documentation of the workaround is the weekly legacy job (`legacy.yml:15-20`).

**Suggested fix:** commit the binaries with the exec bit (`git update-index --chmod=+x …`), which also retires the CI chmod steps; and make the launcher's failure message name the failing path and the permission cause [I5]. **Acceptance:** a fresh clone compiles `tests/hello.sov` with no manual step, on all three OS runners. **Wave 0.**

### F-04 — P1 · Zero end-to-end TLS coverage

**Evidence:** `grep -c "tl_get\|tl_send\|use tls" library/suite.sov` = **0**; `grep -rln "tl_get\|tl_send" tests/` = empty. The suite covers the TLS *primitives* (NIST GCM vectors, RFC 7748 X25519 vectors, HMAC — the "crypto board", `suite.sov:1921-1928`) but never the handshake, record layer, PRF, or certificate path. This is why F-01, F-02, F-05 and F-06 shipped unnoticed. Contrast: the bot libraries *are* tested end-to-end against a local mock HTTP server (`check.yml`, "the bot libraries, against a service we run").

**Suggested fix:** add a local TLS-server board to the suite (same mock-server pattern), plus recorded-handshake fixtures; a self-signed-cert rejection test once F-02 lands. **Acceptance:** the F-01 acceptance check and an F-02 rejection check both exist and fail on the current source. **Wave 1.**

### F-05 — P1 · No TLS extensions (no SNI) → in-language HTTPS fails on most real hosts, silently

**Evidence (static):** the ClientHello is exactly 65 bytes with the extensions length set to zero — `library/tls.sov` (`tl_step_ch`: bytes 41-42 are `0, 0`). No SNI [RFC 6066], no supported_groups, no signature_algorithms. **Evidence (live):** `web_get("https://github.com/")` succeeded (225,280 bytes) **without** tls.sov's handshake prints (see F-06), i.e. via the `/usr/bin/curl` fallback (`web.sov:275-295`); the same client completed a handshake against a permissive local server (prints present). So against SNI-requiring hosts the in-language client fails and `web.sov` silently substitutes curl — the user neither sees the failure nor learns that the "https handled in Sovren, no helper needed" claim (`web.sov:10-13`) did not hold. This also makes the effective runtime dependency external, an I1 tension.

**Suggested fix:** emit the SNI extension (and minimal supported_groups/signature_algorithms) in `tl_step_ch`, and make the helper fallback loud (set `web_last` and print a one-line reason) [I5]. **Acceptance:** the live github fetch prints the tls debug prefix (i.e. the in-language path runs), or the fallback states itself. **Wave 1.**

### F-06 — P2 · Stray debug prints in the production TLS library

**Evidence:** `library/tls.sov:572` — `print peek_byte(tl_rb, 4)` inside `tl_step_ske` (prints a ServerKeyExchange byte, observed value `3`); `library/tls.sov:649` — `print bad` inside the premaster-check (observed `0`). Both fire on **every** handshake, corrupting program stdout for every HTTPS user. No other crypto library has stray prints (grep over aes/gcm/x25519/hmac/sha256/chacha20/poly1305/pbkdf2/hkdf = 0 hits). **Suggested fix:** delete both lines; add a suite check that a TLS round-trip prints only the response. **Wave 1.**

### F-07 — P2 · Unchecked allocation past the 64 MB heap ceiling

**Evidence:** `runtime.sov` `_sov_alloc` advances `heap_ptr` without ever comparing `heap_ptr + size` to `heap_end` (the ceiling is set in `rt_heap`, `runtime.sov:14-19`). Reproducer (`/tmp/r-heap2.sov`): `p: _sov_alloc(67108864)` then `poke_byte(p, 67108863, 1)` — **printed `1`, exit 0**: the write landed past the mapping's end into an adjacent mapped page. Outcome is nondeterministic: segfault or silent corruption of a neighboring mapping. [CWE-788, CWE-131.] **Suggested fix:** check the ceiling and stop with a named error naming the requested size and the ceiling [I5]. **Acceptance:** the reproducer prints the named error and exits 1. **Wave 1.**

### F-08 — P2 · Stack-exhaustion crashes bypass the crash handlers (and the wipe)

**Evidence:** the compiler arms five handlers — ill, abrt, bus, fpe, segv — via `rt_sigaction` (`compilers/linux/compiler.sov:1390`; exit code 100+signal per `:1324`). Division by zero and signed overflow are caught cleanly (live: `print 1 / 0` and `print 9223372036854775807 + 1` both print `trap`, exit 1). But infinite recursion (`/tmp/r-rec.sov`) dies with a **bare SIGSEGV, exit 139, no output**: the fault occurs on the exhausted stack, and without an alternate signal stack (`sigaltstack`/`SA_ONSTACK`) the handler cannot run. Consequences: no honest diagnostic [I5], and for `private` programs the crash-path frame wipe (passes 117/118; `vault.sov:30-32`) does not happen [I6]. The suite's S6 crash checks (`suite.sov:925-929, 1204-1224`) use out-of-bounds pokes, never stack exhaustion. [CWE-674 Uncontrolled Recursion.] **Suggested fix:** install the handlers on an alternate stack, or bound recursion depth at compile time; add a stack-exhaustion suite check. **Wave 2.**

### F-09 — P2 · Super-linear compile time in nesting depth

**Evidence (live, identical program shape, varying depth):** depth 250 → 365 ms; 500 → 2,340 ms (×6.4); 1000 → 16,366 ms (×7.0); 2000 → ≈60 s. Doubling depth quadruples time: O(n²). A ~4 KB adversarial source file stalls the compiler for a minute — a resource-exhaustion vector the S4 hostile-input board (`suite.sov:2484+`) does not bound (it checks crashes, not time). [CWE-400 Uncontrolled Resource Consumption; CWE-674.] **Suggested fix:** reject nesting beyond a fixed depth with a clean error (the "line too long" path at `/tmp/r-nest.sov` shows the pattern), and profile the quadratic pass (candidate: repeated list rebuilds in the expression parser or the relaxation pass 69). **Wave 1.**

### F-10 — P2 · Linux-only syscall libraries compile everywhere, run nowhere else, and say so nowhere

**Evidence:** raw syscall numbers per library — `uid.sov`: 102/104/107 (getuid/getgid/getegid); `walk.sov`: 217 (getdents64); `proc.sov`: 61 (wait4); `file.sov`: 74/77/263 (fcntl/fstat/openat2); `perm.sov`: 90. The Windows bridge's entire import table is 19 Win32 functions (`compilers/windows/compiler.sov:3229-3250`) with no equivalents for these; the macOS bridge maps only 257→2, 56/57/202, 60 (`compilers/macos/compiler.sov:2803-2810`). CI's "every library on every target" step only **builds** (`check.yml`, "every library on every target"). `sys.sov` honestly labels itself "Linux syscalls" (`library/sys.sov:1`); the five libraries above make no platform claim in their headers. This breaks the architecture rule stated in `library/mem.sov` ("a shared library may only use a builtin that every target has") and the honesty principle [I3, I5]. **Suggested fix:** header platform labels, plus a compiler warning when an unmapped syscall number is used on a target (the warning machinery already exists — `Warning: empty`/`Warning: locals`). **Wave 2.**

### F-11 — P2 · Hardcoded `/tmp` paths: parallel-run collisions and a symlink surface

**Evidence:** occurrence counts — `library/suite.sov` 311, `tests/run.sov` 155, `library/testrun.sov` 4, `library/fuzzlib.sov` 4. Library-level fixed temp files: `discord.sov:117,121` (`/tmp/sov-dc-body`) and `web.sov:289,293` (`/tmp/sov-web-body`) — two concurrently running programs using the bot libraries overwrite each other's request bodies (correctness), and a fixed world-readable path in a sticky directory is a classic symlink/TOCTOU surface [CWE-377, CWE-59]. **Suggested fix:** unique paths derived from `rand_bytes` (`rand.sov:4-6`), i.e. an in-Sovren `mktemp` equivalent. **Wave 1.**

### F-12 — P2 · No PBKDF2 iteration floor in `vault`

**Evidence:** `vault_save path data password iters` passes the caller's `iters` straight to `pbkdf2_sha256` (`vault.sov:39-47`); `vault_load` rejects only `iters < 1` (`vault.sov:93-95`). A vault saved with `iters: 1` is weak and loads without complaint. [CWE-916; OWASP Password Storage Cheat Sheet recommends ≥600,000 iterations for PBKDF2-HMAC-SHA256.] **Suggested fix:** floor in `vault_save` with a named error below it. **Wave 2.**

### F-13 — P2 · Most compiler diagnostics lack file:line, though the compiler has them

**Evidence (live):** `Error: no such name / missing` (unknown name); `Error: bad line / prnt 1` (syntax); `Error: cannot read library / nosuchlib` — none name the source location. By contrast the arity error prints all four parts: `Error: wrong number of values / web_get / /tmp/r-tls2.sov / 4`. The compiler tracks `src_name` (`compilers/linux/compiler.sov:59, 2551`) and `err_line` (`:58, 1699`) — they feed the debugger's line maps but are not printed in most error paths [I5]. **Suggested fix:** uniform `Error: <file>:<line>: <message>`. **Wave 1.**

### F-14 — P3 · Out-of-range integer literals silently wrap

**Evidence (live):** `print 99999999999999999999` compiles and prints `7766279631452241919` — no diagnostic. Contrast with the runtime overflow trap (F-08's `trap`), which shows the compiler *can* reject arithmetic overflow; the literal parser does not. [CWE-190.] **Suggested fix:** reject literals outside the i64 range with a named error. **Wave 2.**

### F-15 — P3 · `rand_below`/`rand_range`: modulo bias and a 256-value ceiling

**Evidence:** `library/rand.sov:13-21` — `rand_below n: return rand_u8() % n`. For n=3, residues split 86/85/85 over 256 values; a live 30,000-sample run returned 10043/9868/10089, matching the biased expectation within noise. `rand_range` is likewise capped at a 256-wide span. Currently **latent** — no internal callers (`grep -l rand_below library/` = rand.sov only; vault and tls use `rand_bytes`), but it is the easy-wrong public API. [CWE-338, CWE-330; NIST SP 800-90A.] **Suggested fix:** rejection sampling. **Wave 2.**

### F-16 — P3 · Comment drift (first confirmed instances of the H17 class)

**Evidence:** (a) `runtime.sov` spawn section: "a spawned job must not allocate from the heap yet - the bump pointer is not thread-safe" — but `_sov_alloc` holds an atomic spinlock (`runtime.sov`, `g_alloc_lk` + `atomic_swap`), so spawned jobs *can* allocate; the comment is stale. (b) `bootstrap.sov:13` claims "one 211 KB seed"; the actual seed `compilers/linux/compiler` is 225,144 bytes ≈ 220 KiB. (c) `tls.sov:552` "our ephemeral X25519 keypair" — see F-01. [I5.] **Suggested fix:** correct the comments; add a suite check that CI-comment claims about sizes stay true (or drop the size from the comment). **Wave 1.**

### F-17 — P3 · Unactionable warning text

**Evidence:** `compilers/linux/compiler.sov:1936` prints `Warning: locals` plus the job name and two counts — no source line, no remedy; triggered by an ordinary `try/except` function (live). `Warning: empty` (`:1822`) *does* print the line — inconsistent. The CI "no warnings from any compiler" gate (`check.yml`, "no warnings from any compiler") only covers building the compilers themselves, so user-facing warning quality is ungoverned. **Suggested fix:** name file:line and one remedy sentence for both warnings. **Wave 3.**

### F-18 — P3 · Helper stderr leaks; TLS failures carry no reason

**Evidence (live):** a `web_get` run printed `Unknown database: hosts github.com` on stderr — the `/usr/bin/getent` helper's raw error (`web.sov:170-176` invokes it via `tool_out`, which does not capture stderr). Also: after a failed `tl_get`, `web_why()` still returned `0` (WEB_OK) — the TLS path sets no reason code, so callers cannot distinguish failure causes [I5]. **Suggested fix:** capture or silence helper stderr; set a distinct `web_last` code for TLS failure. **Wave 3.**

### F-19 — P2 · Fuzzer immaturity (testing-strategy finding)

**Evidence:** `library/fuzzlib.sov` — LCG PRNG `fz_next` (`:18-23`), fixed seeds (`fz_seed: 12345` in the library, `987654321` in `tests/fuzz_run.sov:5`), 300 programs per run (`fuzz_run.sov:7`), grammar limited to arithmetic expressions / if / loop (`fuzzlib.sov` header). No corpus persistence, no minimization, no coverage feedback; the S4 hostile-input board is a fixed list of seven hand-written cases (`suite.sov:2485-2493`). The oracle design (self-evaluator, `fuzzlib.sov` header) is sound for its grammar but covers no statements, jobs, or libraries. **Suggested fix (in-Sovren, I8):** extend `fuzzlib.sov` with corpus persistence, mutation operators, and an optional per-run seed — keeping the fixed seed as the regression default [I7]; use the in-language emulator's step trace as coverage feedback. **Wave 3.**

### F-20 — P2 · Test-battery architecture (testing-strategy finding)

**Evidence:** `library/suite.sov` is 182 KB and holds all 551 checks in one file; `tests/fast.sov` hardcodes the 14-item skip list (`fast.sov:20-36`). The two-tier design and the skip-list *documentation* are good practice; the scale is the risk (merge friction, one corruption affects everything). Any decomposition must preserve the "one list of checks, two ways to run it" property (`all.sov:1-8`) and the no-build-system rule [I1, I3]. **Suggested fix:** optional split into per-board files `use`d by a thin `suite.sov`, with the skip list becoming data. **Wave 3.**

---

## 3. Positive observations (verified working — the audit is not one-sided)

- **Reproducibility proof holds:** bootstrap clean, seed fixed point g3==g4==g5, ten artifacts byte-identical (26.3 s) — the committed binaries are provably the build of the committed source.
- **Battery green:** 551/551 checks, including emulator runs of real guests, PE/Mach-O cross-execution, NIST/RFC crypto vectors, privacy-board enforcement (capability-free compiler source, no build metadata, bit-identical rebuilds — `suite.sov:1928-1937, 2141-2177`).
- **Runtime honesty:** division by zero and signed overflow both trap cleanly (`trap`, exit 1) rather than corrupting.
- **FFI is real:** `cffi.sov` loaded the host libc and called `strlen` correctly (live: returned 11).
- **Concurrency works:** spawn/join round-trip returned the expected 49; the race detector's four suite checks pass.
- **REPL and `sovren-dbg` both function** (line-attributed stepping verified).
- **Cross-target compile:** all seven target flags produce well-formed binaries in 2–10 ms.
- **DNS short-circuit:** numeric IP literals need no helper (`web.sov:170-176, 196-215`).

---

## 4. Hypotheses register — status after Phases 0–1

| # | Status | Note |
|---|---|---|
| H1 seed provenance | **confirmed as design** (I2) | The seed is the axiom; bootstrap proves freshness. Recommendation: provenance documentation + emulator-based behavioral verification — not regeneration. |
| H2 RNG bias | **confirmed** | F-15; latent internally. |
| H3 unchecked indexing | **confirmed as design intent** (I4) | Not filed as a bug; see roadmap §4.1. |
| H4 allocator ceiling | **confirmed as gap** | F-07 — no ceiling check exists. |
| H5 crypto unaudited | **confirmed, worse than hypothesized** | F-01, F-02, F-05, F-06. |
| H6 vault AAD gap | **refuted as practical risk** | All header fields (iters/salt/nonce) are KDF inputs, so any tampering changes the key and fails the GCM tag (`vault.sov:93-120`). Residual: the format comment is self-contradictory ("aad is the header itself is NOT covered") — documentation fix only (Info). |
| H7 per-target divergence | **pending** (Phase 4) | Shared-core byte-identity not yet mechanically verified. |
| H8 fuzzer narrowness | **confirmed** | F-19. |
| H9 meta-circularity | **open** | Mitigations verified present; residual-risk statement due in Phase 5. |
| H10 `/tmp` isolation | **confirmed** | F-11. |
| H11 no coverage/mutation/benchmark gates | **confirmed** | No such tooling found; Phase 5 to quantify. |
| H12 no README/docs | **confirmed** | No README, docs/, CONTRIBUTING; Phase 6. |
| H13 supply chain | **partially confirmed** | Artifacts proven fresh (bootstrap); exec-bit defect found (F-03); workflow tag-pinning deferred to Phase 6. |
| H14 global-state coupling | **pending** (Phase 4) | |
| H15 suite monolith | **confirmed** | F-20. |
| H16 single-commit history | **confirmed** | `git log` shows exactly one commit. |
| H17 comment/code drift | **confirmed** | F-16 gives two live instances. |
| H18 privacy invariant | **partially verified** | Suite enforces it; full extraction of the compiler's syscall surface pending in Phase 2. |

---

## 5. Session limitations (honesty per I5)

- Per-check timing (`tr_time`) requires editing `testrun.sov`, which the read-only ground rule forbids; the battery's total time is reported instead.
- The emulator step-rate baseline (2.5 M steps/s) is a CI comment figure (`check.yml`, emulator-build step), not re-measured here.
- Windows/macOS runtime behavior cannot be exercised on this Linux host; cross-target claims rest on compile checks plus the suite's emulator-based cross-execution.
- The live TLS tests targeted `127.0.0.1` servers run by this session and `github.com` (an allowed host); no third-party service was probed.
- Findings F-02's severity assumes certificates *should* be validated; if the maintainers decide otherwise (design decision), it reclassifies to a documentation fix.

---

## 6. References

**Repository evidence (primary):** `library/tls.sov:336-340, 523-539, 552-560, 572, 649`; `library/rand.sov:4-21`; `runtime.sov` (`_sov_alloc`; `heap_end` appears only in `rt_heap`, never in `_sov_alloc`); `library/vault.sov:39-47, 93-120`; `library/web.sov:10-13, 170-176, 275-295`; `library/discord.sov:117-121`; `library/mem.sov` (universal-builtin rule); `library/secret.sov`; `library/fuzzlib.sov:18-23`; `library/suite.sov:1921-1937, 2141-2177, 2484-2493`; `compilers/linux/compiler.sov:58-59, 1324, 1390, 1822, 1936, 2551`; `compilers/windows/compiler.sov:3194-3250`; `compilers/macos/compiler.sov:2803-2810`; `launcher.sov` (`lc_exec`); `bootstrap.sov:13`; `.github/workflows/check.yml:283-310, 339-344`; `.github/workflows/legacy.yml:15-20`; `git ls-files -s` (committed modes); `git log` (single commit).

**External standards (secondary):** CWE-190, CWE-295, CWE-330, CWE-338, CWE-345, CWE-377, CWE-400, CWE-59, CWE-674, CWE-788, CWE-916 (MITRE, https://cwe.mitre.org); RFC 5246 §7.4.1.2 (ClientHello.random), RFC 7748 §3 (X25519 key generation), RFC 6066 (SNI); NIST SP 800-90A (random bit generation); OWASP Password Storage Cheat Sheet (PBKDF2 iteration floor); OWASP Secure Code Review Cheat Sheet (process); Intel, *Guidelines for Mitigating Timing Side Channels* (constant-time discipline); Chen et al., *A Survey of Compiler Testing*, CSUR 2020 (differential testing); roadmap Appendix D for the full list.

---

*Phase 0 and Phase 1 of the roadmap are complete. The repository was not modified. Next: Phase 2 (security deep-dive, informed by F-01/F-02/F-05), Phase 3 (performance, informed by F-09), Phase 4 (architecture), Phase 5 (testing strategy, informed by F-04/F-19/F-20), then Phase 7 synthesis and the Phase 8 Resolution Plan.*
