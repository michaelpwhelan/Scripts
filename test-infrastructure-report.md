# Test Infrastructure Report

**Repository:** Scripts
**Date:** 2026-03-22
**Scope:** Python (logparse + fuzzer) and PowerShell

---

## 1. Current State

### Scale

| Language | Source LOC | Test LOC | Test Density | Test Files |
|----------|-----------|----------|--------------|------------|
| Python (logparse) | ~21,800 | ~17,400 | 0.79:1 | 20+ |
| Python (fuzzer) | ~6,000 | ~385 | 0.06:1 | 5 |
| PowerShell | ~48,500 | ~515 | 0.01:1 | 1 |
| **Total** | **~76,300** | **~18,300** | **0.24:1** | **26+** |

### Frameworks

| Framework | Language | Where Used |
|-----------|----------|------------|
| pytest | Python | `tests/test_parsers.py`, `tests/test_fuzz_*.py` |
| unittest | Python | `fuzzer/tests/` (5 modules) |
| Custom standalone runner | Python | 14 `test_*.py` suites in logparse root |
| Pester | PowerShell | `Rename-ManagedComputer.Tests.ps1` |

### Test Suites (Python/logparse)

**Pytest-based unit tests** (`tests/` directory):
- `test_parsers.py` (826 LOC) -- all 8 parsers, fixture-based + inline
- `test_fuzz_1000.py` / `test_fuzz_10k.py` -- parametrized command fuzzing

**Standalone behavioral suites** (logparse root):

| Suite | LOC | Cases | Domain |
|-------|-----|-------|--------|
| test_resolver.py | 1,898 | ~200 | Field name resolution, context detection |
| test_parser_fidelity.py | 1,553 | 132 | Field-by-field extraction accuracy |
| test_analyzer_detection_rates.py | 1,308 | 86 | Analyzer sensitivity/specificity |
| test_filter_engine_correctness.py | 1,137 | 106 | Filter logic truth tables |
| test_visual_rendering.py | 1,133 | 71 | Chart rendering |
| test_session_state_machine.py | 956 | 82 | Undo/redo, annotations, tags, snapshots |
| test_export_roundtrip.py | 934 | 53 | Export format integrity |
| test_verbose_output.py | 923 | 8 | Dashboard rendering |
| test_report_output_structure.py | 849 | 91 | Report schema validation |
| test_pipeline_algebra.py | 832 | 81 | Operator composition |
| test_enrichment_accuracy.py | 809 | 120 | GeoIP, ASN, MITRE, threat intel |
| test_noise_profile_effectiveness.py | 731 | 53 | Noise filtering |
| test_platform_compatibility.py | 725 | 62 | Cross-platform |
| test_command_dispatch_coverage.py | 685 | 78 | Command registry routing |

**Integration & orchestration:**
- `logparse_integration_tests.py` (2,162 LOC, 229 REPL-based cases)
- `logparse_test_all.py` (1,266 LOC, meta-orchestrator with HTML output)
- `logparse_testdata.py` (2,093 LOC, synthetic log generator for all 8 formats)
- `logparse_fuzzer.py` (1,679 LOC, fuzzer entry point)
- `test_fuzz_commands.py` (1,286 LOC, syntax + workflow fuzz modes)

**Fuzzer unit tests** (`fuzzer/tests/`):
- `test_models.py` -- FuzzResult classification, fingerprinting, clustering
- `test_executor.py` -- skip/timeout logic
- `test_oracles.py` -- output validation, pipeline detection
- `test_protocol.py` -- generator discovery, SPEC validation
- `test_scheduler.py` -- adaptive mode scheduling

### Test Data & Fixtures

Fixture directory: `logparse-test-fixtures/` with realistic logs across all 8 formats (FortiGate, FortiSwitch, FortiClient, JSONL, Windows XML, raw text, FortiGate conf, EVTX).

`logparse_testdata.py` generates synthetic data modeled on a credit union environment: 5 sites, IP pools for workstations/servers/VPN/voice/FortiLink, March 2026 timestamps.

### Latest Fuzz Run (2026-03-22)

| Metric | Value |
|--------|-------|
| Commands tested | 3,690 |
| OK | 3,559 (96.4%) |
| Crashes | 0 |
| State corruption | 0 |
| Timeouts (>8s) | 19 |
| Slow (>5s) | 112 |

Common timeout pattern: `export summary` in multi-command chains. No crashes or state corruption detected.

---

## 2. Strengths

**Breadth of test layers.** The logparse project has unit, behavioral, integration, and fuzz testing. Few projects at this scale have all four.

**Dual execution model.** Standalone suites run without pytest (exit code 0/1, JSON/HTML reports) and also work as pytest modules. This removes framework lock-in and enables quick smoke testing.

**Realistic test data.** `logparse_testdata.py` generates environment-accurate synthetic logs rather than minimal stubs. Fixture files cover real-world formats and volumes.

**Fuzz harness maturity.** 13 generator modes (adversarial, boundary, mutation, regression, differential, scaling, semantic, etc.), oracle validation, adaptive scheduling, SQLite result storage, and HTML/Markdown reporting. The fuzzer is a serious tool, not a toy.

**Session state machine coverage.** `test_session_state_machine.py` explicitly tests undo/redo, filter snapshots, hide rules, annotations, tags, and notes -- the areas where interactive tools break most often.

**Zero crashes in fuzzing.** 3,690 command sequences with zero crashes and zero state corruption is a strong signal.

---

## 3. Gaps

### 3.1 No CI/CD Pipeline

No GitHub Actions, Jenkins, GitLab CI, or any automation. Every test run is manual. This means:
- Regressions can land on `main` without detection.
- No test runs on PR branches.
- No gating on test passage before merge.
- No historical trend data on test health.

**Risk: High.** This is the single biggest gap.

### 3.2 No Code Coverage Measurement

No `pytest-cov`, no `.coveragerc`, no coverage reporting anywhere. The test density ratio (0.79:1) looks good, but there is no way to know which lines and branches are actually exercised. Modules like `cache.py`, `config_loader.py`, `cli.py`, and `geoip.py` have no dedicated tests and are only hit indirectly -- but nobody can verify that without coverage data.

**Risk: Medium.** Without coverage metrics, "well-tested" is a feeling, not a measurement.

### 3.3 PowerShell: Nearly Untested

34 production PowerShell scripts totaling ~48,500 LOC. One Pester test file (515 LOC) covering one script. Everything else -- `Audit-FortiGatePolicies.ps1` (3,258 LOC of security audit logic), the entire helpdesk toolkit (11 scripts), the Intune diagnostics suite, the FortiGate config differ -- is untested.

These scripts interact with Active Directory, Microsoft Graph, Intune, FortiGate APIs, and remote systems. They modify passwords, rename computers, change group memberships, and revoke accounts. The blast radius of bugs here is high and the test coverage is near zero.

**Risk: High.** Critical operational scripts with external side effects and no tests.

### 3.4 Happy-Path Bias in Behavioral Suites

The standalone `test_*.py` suites construct known-good data, execute commands against it, and assert expected output. This catches regressions in normal behavior but misses:

- **Malformed input:** truncated log lines, encoding errors, BOM markers, mixed formats in one file
- **Empty/degenerate results:** filters that match nothing, parsers fed empty files, pipelines with zero events
- **Boundary values:** single-event datasets, maximum field lengths, deeply nested JSON
- **Failure paths:** missing config files, permission errors, invalid regex in user filters

The fuzz harness addresses some of this, but the behavioral suites themselves are exclusively happy-path.

**Risk: Medium.** Particularly relevant for the parsers, which consume untrusted external data.

### 3.5 Stateful Sequence Coverage Remains Thin

This was previously identified and remains the most significant quality gap. The fuzz harness runs multi-command sequences (which is good), but the behavioral test suites largely reset state between tests. Real user sessions accumulate state: filters stack, stars persist, annotations interact with exports, variables change what commands see.

The `test_session_state_machine.py` suite tests individual state operations but doesn't test long chains of interleaved operations. The fuzz run found 19 timeouts in multi-command chains -- these hint at interaction effects that isolated tests would never surface.

**Risk: Medium-High.** This is where manual testing still finds bugs that automated tests miss.

### 3.6 Performance Testing Is Incidental

112 slow commands (>5s) and 19 timeouts in the fuzz run, with `export summary` as the common trigger. There is no dedicated performance test suite, no baseline benchmarks, and no regression detection for performance. The fuzz report flags outliers but nothing prevents performance from degrading silently between changes.

**Risk: Low-Medium.** Important for user experience but not correctness.

### 3.7 No conftest.py or Shared Pytest Fixtures

The `tests/` directory has no `conftest.py`. Each test file sets up its own session, loads its own data, and defines its own helpers. The standalone suites use a custom `TestContext` and custom assertion helpers. This means:
- Fixture loading logic is duplicated across suites
- No shared pytest fixtures for common patterns (loaded session, parsed events, etc.)
- Switching between the custom runner and pytest idioms adds friction

### 3.8 Fuzzer Internals Under-Tested

The fuzzer package itself is ~6,000 LOC with only ~385 LOC of tests (0.06:1 ratio). The 5 unit test files cover models, executor, oracles, protocol, and scheduler -- but the 13 generator modules, the database layer, the grammar module, the minimizer, and the report generators have no tests. If the fuzzer silently generates invalid commands or misclassifies results, the main test results become unreliable.

**Risk: Low-Medium.** A meta-testing problem -- bugs in the test tool itself.

---

## 4. Recommendations

### Immediate (Low Effort, High Impact)

1. **Add `pytest-cov` to dev dependencies and a coverage target.** Even a rough first measurement reveals blind spots. Add `--cov=logparse --cov-report=term-missing` to the default pytest invocation in `pyproject.toml`.

2. **Add a GitHub Actions workflow for `pytest tests/`.** A minimal CI pipeline that runs on push to `main` and on PRs. Even if it only runs the fast unit tests (not the full fuzz suite), it gates merges on basic correctness.

3. **Create `tests/conftest.py` with shared fixtures.** A `loaded_session` fixture that parses the standard test fixtures once per session, plus a `fresh_session` fixture that resets state per test. This eliminates fixture setup duplication.

### Short-Term (Moderate Effort)

4. **Add negative/edge-case tests to the parser suite.** Each parser should have explicit tests for: empty input, single malformed line, truncated mid-field, BOM-prefixed, encoding errors, and mixed-format files. These are the inputs that come from real-world log collection and break parsers.

5. **Build a stateful sequence test suite.** Not fuzz -- deterministic multi-step scenarios that exercise known-problematic interaction patterns:
   - `where` -> `count` -> `undo` -> `show` -> `export`
   - `star` + `annotate` + `hide` + `export` (compound state)
   - Command after `where` that narrows to zero results
   - Variable-dependent command after the variable is redefined

6. **Add `export summary` performance benchmarks.** The fuzz report shows this is the common timeout trigger. A targeted benchmark suite that measures `export summary` latency under various state conditions would catch performance regressions and guide optimization.

### Medium-Term (Higher Effort)

7. **Pester tests for high-risk PowerShell scripts.** Priority order:
   - `Audit-FortiGatePolicies.ps1` (security audit logic with complex branching)
   - `Reset-UserPassword.ps1` and `Rename-ManagedComputer.ps1` (modify AD/Entra state)
   - `Set-GroupMembership.ps1` (bulk permission changes)
   - `Unlock-UserAccount.ps1` (account state changes)

   Focus on testing the pure logic (parameter validation, decision branching, output formatting) with mocked external dependencies (AD, Graph, FortiGate).

8. **Extend CI to run the integration suite and a fuzz subset.** The full 10k fuzz run is too slow for CI, but `test_fuzz_1000.py` or a `--quick` subset of `test_fuzz_10k.py` would add meaningful coverage without excessive runtime.

9. **Add fuzzer self-tests.** At minimum, the generator modules should have tests verifying they produce syntactically valid commands, and the database layer should have tests verifying result storage/retrieval correctness.

### Long-Term

10. **Coverage-gated CI.** Once coverage measurement is in place and baseline coverage is established, add a coverage threshold to CI so that coverage cannot decrease without explicit approval.

11. **Property-based testing for parsers.** Use Hypothesis to generate arbitrary log lines conforming to each format's grammar and verify that parsing never crashes and always produces valid `LogEvent` objects. This is a more principled complement to the fuzz harness.

---

## 5. Summary

The logparse Python project has strong test infrastructure -- multiple test layers, a mature fuzzer, realistic fixtures, and broad coverage of its feature surface. The main weaknesses are operational: no CI/CD automation, no coverage metrics, and thin PowerShell testing. The known testing gap around stateful sequences has been partially addressed by the fuzzer but not yet by deterministic behavioral tests.

The highest-leverage improvements are adding CI (prevents regressions from landing), coverage measurement (turns intuition into data), and PowerShell Pester tests for the scripts that modify external state.
