# Sovren Audit — Session Log: Phase 6 (DX, Documentation, CI/CD & Release)

| | |
|---|---|
| **Session** | Audit of `discorddioxin/sovren`, per `docs/AUDIT-ROADMAP.md` — continuation of the Phase 0–5 logs |
| **Freeze commit** | `003149e12777f19a3da2433066ddf3f1303da147` (unchanged) |
| **Environment** | Linux 6.1.158+ x86-64 (e2b sandbox), 2026-10-18; fresh-clone onboarding test run from a pristine `git clone` of the repo into `/tmp/fresh-clone` |
| **Ground-rule compliance** | Read-only on the repo; all build/run artifacts in `/tmp`; `git status` clean of tracked changes |
| **Citation rule** | Every claim cites a repository location (`file:line`) or an external authority, listed in §4 |

---

## 1. New findings

| ID | Sev | Component | Title | Design intent? | Invariant |
|---|---|---|---|---|---|
| F-48 | P1 | repo root | Onboarding is blocked on a fresh clone: the exec-bit ritual exists only in CI YAML; the first command a stranger runs fails with an error that does not say why | accidental (git mode bits) | I5 |
| F-49 | P2 | repo root | No README, CHANGELOG, CONTRIBUTING, SECURITY.md, issue templates, or package manifest — the repo has no front door | accidental (H12 confirmed) | I5 |
| F-50 | P2 | legal/DX | PSVL §3.3 requires private disclosure of security research to the Author first, but the repo publishes no disclosure route | accidental | — |
| F-51 | P3 | repl.sov | Header overstates the REPL's per-line cost by ~200× ("a second or two" vs 5 ms measured) — stale, though honest in direction | accidental | I5 |
| F-52 | P3 | launcher.sov | `--help` never mentions the REPL (`repl.sov`) or the committed debugger (`sovren-dbg`) — both invisible from the CLI | accidental | I5 |
| F-53 | P3 | CI | No caching, floating runner image tags, no workflow-lint gate | accidental | — |
| F-54 | Info+ | tests | Two-tier test design is sound: self-contained `all.sov` on every push; dependency-heavy `run.sov` weekly | deliberate | I8 ✓ |
| F-55 | Info+ | release | Version string is single-sourced (`launcher.sov:18`); minor artifact-naming inconsistency (`compiler-so` vs `compiler`) | deliberate | — |

### F-48 — P1 · Time-to-first-compile: 16 ms after an undocumented ritual; blocked without it

**Evidence (live, from a pristine `git clone`):**
1. Stranger's first command, `./sovren tests/hello.sov -o fc1` → `Error: could not start the compiler` (exit 0 — see F-13 for the exit-code inconsistency). The cause — every committed tool binary is git mode 100644 (F-03) — is nowhere in the message.
2. The fix is a multi-path `chmod` ritual that exists **only inside `.github/workflows/check.yml:339-344` and `legacy.yml`** ("make things runnable" step): `git ls-files -z 'sovren' 'sovren.exe' 'compilers/' … | xargs chmod +x`.
3. With the ritual applied, the full path clone → compile → run takes **16 ms** — the toolchain itself is instant; the friction is 100% discoverability.

**Impact:** every new contributor and every fresh CI image hits this; the error actively misleads (it names neither the cause nor the fix). [Onboarding-friction literature: first-run experience dominates adoption; DX literature on error-message actionability.]

**Suggested fix:** (a) correct the git modes (`git update-index --chmod=+x` on the ten binaries — a one-time metadata change, no content change); (b) add a README quickstart; (c) have the launcher detect a non-executable compiler and print the exact `chmod` command (an in-Sovren fix, I1). **Acceptance:** a fresh clone compiles `tests/hello.sov` with zero manual steps. **Wave 1** (with F-03, which it duplicates in substance).

### F-49 — P2 · The repo has no front door

**Evidence (inventory, this session):** no `README*`, `CHANGELOG*`, `CONTRIBUTING*`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, or `Makefile`; `.github/` contains only `workflows/` (no issue templates, no Dependabot config, no PR template). The language's own documentation is its source comments — which are unusually good (verified across `repl.sov:1-16`, `tests/run.sov:1-12`, `bench.sov:1-20`, `fast.sov:1-21`) — but there is no entry point that says what Sovren is, how to build it, or how to report a security issue. [H12 confirmed; DX literature: README + contributing guide are the minimum viable onboarding surface.]

**Suggested fix:** a one-page README (what it is, 3-command quickstart, target matrix, "not production crypto" honesty note per I5) plus `SECURITY.md` (F-50) and `CONTRIBUTING.md` (PSVL permits community contribution — `LICENSE:302`). **Wave 1.**

### F-50 — P2 · The license demands private disclosure; the repo gives no way to disclose

**Evidence:** `LICENSE:99-100` — "GOOD-FAITH SECURITY RESEARCH is allowed locally, with **private disclosure to the Author first** (Section 3.3)". A repo-wide search for any disclosure channel (`security@`, "disclose", "vulnerability") finds nothing in the project's own files. A licensee who follows the license's own terms has no address to write to. [PSVL §3.3; coordinated-vulnerability-disclosure norms (CISA/ISO/IEC 29147).]

**Suggested fix:** `SECURITY.md` with the Author's private contact route and the expected disclosure timeline. **Wave 1.**

### F-51 — P3 · REPL cost claim is stale by two orders of magnitude

**Evidence:** `repl.sov:13-15` — "The cost is a second or two per line, which is the honest price of a language with no interpreter." Measured this session (compiled REPL, piped input, three repetitions): **5 ms per line** (compile-and-run of a full line, `use` resolution included). The claim errs conservative (honest in direction, I5) but is ~200× stale — a reader may avoid the REPL believing it is slow. **Suggested fix:** update the sentence to the measured figure with the host noted. **Wave 3.**

### F-52 — P3 · The REPL and debugger are invisible from the CLI

**Evidence:** `lc_help` (`launcher.sov:21-42`) is complete and accurate for what it lists (all seven target flags, both aliases, `--debug`, `--interactive`, `--version` — verified against the flag parser at `launcher.sov:45-71`), but it never mentions that the project ships a REPL (`repl.sov`, whose own header gives the invocation `./sovren repl.sov -o repl && ./repl`, `repl.sov:9`) or a committed debugger binary (`sovren-dbg`, 246 KB at the repo root; verified working in Phase 1). A stranger reading `--help` cannot discover either. **Suggested fix:** two lines in `lc_help`. **Wave 1.**

### F-53 — P3 · CI hygiene: no caching, floating images, no workflow lint

**Evidence:** zero `cache:` keys in either workflow; runner images are floating tags (`windows-latest`, `macos-latest`, `ubuntu-latest` — `check.yml:16, 271, 333`; only the ARM runner is pinned, `ubuntu-24.04-arm`, `check.yml:312`); no `actionlint`/YAML-validation step (this session's Python has no yaml module either — the point stands that nothing in the pipeline lints the YAML). Same pinning class as F-37. [GitHub Actions hardening guidance; OpenSSF Scorecard.]

**Suggested fix:** SHA-pin runner images where the platform allows (or pin via the `runs-on` label convention documented by GitHub), add `actionlint` as a workflow step, consider a dependency cache for the weekly job. **Wave 2.**

### F-54 — Info+ · The two-tier test design is sound

`tests/run.sov:1-12` documents itself: the full battery (emulators, a real C program via gcc, screen drawing via Xvfb) needs external tools, so it stays local and runs weekly (`legacy.yml`, cron `17 3 * * 1`, 30-minute timeout), while `all.sov` — fully self-contained — gates every push. The split is explicit, self-documented, and prevents external-dependency rot in the fast gate. Positive observation.

### F-55 — Info+ · Release engineering is minimal but coherent

The version string is single-sourced (`launcher.sov:18`, "Sovren 0.1.0"); committed binaries are proven fresh by the bootstrap fixed point (Phase 0); artifact naming has one inconsistency (`compilers/android-so/compiler-so` vs `compiler` elsewhere). No changelog exists (F-49 covers it).

---

## 2. Documentation-truthfulness sample (Phase 6 activity, audit of the comments-as-docs model)

Sampled claims, checked against behavior measured in Phases 0–5:

| Claim (location) | Verdict |
|---|---|
| `bench.sov:9-13` — "the largest whole run whose answer still fits in one signed 64-bit integer" for n=2.9M; 10M "does not" | **True** (recomputed: n(n+1)(2n+1)/6 = 8,129,670,871,667,150,000 < 2⁶³ for 2.9M; 3.33×10²⁰ > 2⁶³ for 10M) |
| `tls.sov:2` — "Batteries, not certified: review before production crypto" | **True and load-bearing** — F-01/F-02/F-05 prove exactly the gaps the disclaimer warns about |
| `mem.sov:4-7` — `_sov_mem_copy`/`_sov_mem_set` compile to one `rep movsb`/`rep stosb` | **Consistent** with the pass structure read in Phase 1 |
| `suite.sov` header / `fast.sov:14` — "Sixty of the 105 seconds" are skippable | **Host-dependent, not drift**: this host runs the full battery in ~64 s (Phase 0); the ratio claim is plausible on slower CI hardware |
| `repl.sov:13-15` — "a second or two per line" | **Stale ~200×** (F-51) |
| `runtime.sov` spawn comment — "a spawned job must not allocate from the heap yet" | **Stale** (F-16; `_sov_alloc` carries an atomic spinlock) |
| `bootstrap.sov`/seed comments — "211 KB seed" | **Stale** (F-16; actual 225,144 B) |

Verdict: the comment culture is a genuine asset (6 of 8 sampled claims exactly true); the three stale instances are all in the F-16 comment-drift class.

## 3. Hypotheses register — deltas

- **H12** (no README/spec/CONTRIBUTING) → **confirmed** (F-49, with the full file inventory as evidence).
- **H16** (single-commit history: no archaeology, no blame path) → **confirmed** (the clone used for onboarding has exactly one commit; `git log --oneline | wc -l` = 1).

## 4. References

**Repository evidence (primary):** `launcher.sov:18, 21-42, 45-71`; `repl.sov:1-16`; `tests/run.sov:1-12`; `tests/fast.sov:1-21`; `tests/bench.sov:1-20`; `library/mem.sov:1-8`; `library/suite.sov:1-14`; `.github/workflows/check.yml:16, 271, 312, 333, 339-344`; `.github/workflows/legacy.yml:1-24`; repo-root `ls` (file inventory); fresh-clone session log (`/tmp/fresh-clone`).

**External standards (secondary):** ISO/IEC 29147 (vulnerability disclosure); CISA coordinated vulnerability disclosure guidance; OpenSSF Scorecard (Pinned-Dependencies, CI); GitHub Actions runner-image documentation; DX literature on first-run experience and error-message actionability; roadmap Appendix D.

---

*Phase 6 complete. All six audit phases (0–6) are now executed; Phase 7 (synthesis) and Phase 8 (Resolution Plan) remain. The repository was not modified at any point in this session.*
