# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ianua-broker-v1.0.0...ianua-broker-v1.1.0) (2026-08-12)


### Features

* wave 2 — detection reach and quiet-read surfaces (Blue Report 2026) ([#81](https://github.com/IRsoctierDT/IANUA-Broker/issues/81)) ([cb77f70](https://github.com/IRsoctierDT/IANUA-Broker/commit/cb77f701e80cdb506874882cdcfdc4ce7eca8474))

## [1.0.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ianua-broker-v1.5.0...ianua-broker-v1.0.0) (2026-08-12)


### Features

* **adapters:** add Cursor host adapter ([#23](https://github.com/IRsoctierDT/IANUA-Broker/issues/23)) ([443b65a](https://github.com/IRsoctierDT/IANUA-Broker/commit/443b65a156dd8e0a6c8238079900b5e6d625f671))
* **adapters:** add VS Code host adapter (native MCP) ([#33](https://github.com/IRsoctierDT/IANUA-Broker/issues/33)) ([4b144de](https://github.com/IRsoctierDT/IANUA-Broker/commit/4b144dea6ee9232caf6f6e8dae187917e1f57e22))
* **adapters:** add Windsurf and Cline host adapters ([#26](https://github.com/IRsoctierDT/IANUA-Broker/issues/26)) ([a3f9325](https://github.com/IRsoctierDT/IANUA-Broker/commit/a3f9325e2a9b45a19088896104f9330c016b2b3c))
* **adapters:** add Zed host adapter with JSONC support ([#36](https://github.com/IRsoctierDT/IANUA-Broker/issues/36)) ([a5a87b1](https://github.com/IRsoctierDT/IANUA-Broker/commit/a5a87b1e7b2499880763c7461e95581ed5bbabc2))
* add optional [crypto] ed25519 and [yaml] Continue extras ([#43](https://github.com/IRsoctierDT/IANUA-Broker/issues/43)) ([2bdd484](https://github.com/IRsoctierDT/IANUA-Broker/commit/2bdd4847ee3511c0214808bf50e59364978d523a))
* **atlas:** add Tier-2 framework mapping command ([#51](https://github.com/IRsoctierDT/IANUA-Broker/issues/51)) ([bf7511f](https://github.com/IRsoctierDT/IANUA-Broker/commit/bf7511fe4a5fae8e0e6d9183147ce4e0b1934c46))
* **dogfood:** add Phase-2 tooling — config anonymizer and network-lab runbook ([#55](https://github.com/IRsoctierDT/IANUA-Broker/issues/55)) ([5f63052](https://github.com/IRsoctierDT/IANUA-Broker/commit/5f63052dca40cc90197add7d01802d4cff39f5f3))
* **drift:** add Tier-5 baseline + diff drift detection ([#56](https://github.com/IRsoctierDT/IANUA-Broker/issues/56)) ([77aadbd](https://github.com/IRsoctierDT/IANUA-Broker/commit/77aadbd7ddaed80b42980bce1bdc0b569ef3295b))
* **fix:** add opt-in --fix for over-broad tool-scope grants ([#31](https://github.com/IRsoctierDT/IANUA-Broker/issues/31)) ([2fafad8](https://github.com/IRsoctierDT/IANUA-Broker/commit/2fafad80e1bc94b155c5f1c8043cea6b6707cac3))
* **inventory:** add Tier-1 AI/MCP asset inventory command ([#49](https://github.com/IRsoctierDT/IANUA-Broker/issues/49)) ([0fe0f9f](https://github.com/IRsoctierDT/IANUA-Broker/commit/0fe0f9fadddfd5d885215ba19150257ef9211309))
* **lan:** add mcpscan lan Phase A safety core (authorization, no network) ([#38](https://github.com/IRsoctierDT/IANUA-Broker/issues/38)) ([5b661c9](https://github.com/IRsoctierDT/IANUA-Broker/commit/5b661c92aa3cf681f60e946b4c12630bdfdacb77))
* **lan:** enterprise-policy gate for public targets + operator guide ([#42](https://github.com/IRsoctierDT/IANUA-Broker/issues/42)) ([91680fe](https://github.com/IRsoctierDT/IANUA-Broker/commit/91680fe9230a061c0e0b2b14851a988aecff5fa6))
* **lan:** SARIF logical locations for network-endpoint findings (ADR-16) ([#53](https://github.com/IRsoctierDT/IANUA-Broker/issues/53)) ([2b46434](https://github.com/IRsoctierDT/IANUA-Broker/commit/2b464342e4015c0518d1d174a7dfb61dbaec4d91))
* **lan:** wire the mcpscan lan command on the safety core ([#40](https://github.com/IRsoctierDT/IANUA-Broker/issues/40)) ([44da233](https://github.com/IRsoctierDT/IANUA-Broker/commit/44da233cd858fb69faa9864be36dbc5408cd5549))
* **report:** add SARIF 2.1.0 output and code-scanning workflow ([#28](https://github.com/IRsoctierDT/IANUA-Broker/issues/28)) ([f1971c5](https://github.com/IRsoctierDT/IANUA-Broker/commit/f1971c558b6f695b27f25ec278bc7fabbf6bebcc))
* **sprint-1:** foundations — domain model, path resolver, safe reader, CI ([2cb9d64](https://github.com/IRsoctierDT/IANUA-Broker/commit/2cb9d641ddbe779c82ed26b4331828a7201a5647))
* **sprint-2:** core engine — discovery, Claude adapter, 4 check families, scoring ([48938ba](https://github.com/IRsoctierDT/IANUA-Broker/commit/48938bac431e3f2685a08e06d4a2653bedce2a29))
* **sprint-3:** reporting — terminal, stable JSON, self-contained HTML ([0e87f56](https://github.com/IRsoctierDT/IANUA-Broker/commit/0e87f5652e16beb9f9a1adff2854b45e8e3af97e))
* **sprint-4:** online enrichment, self-scan, security sign-off, docs ([25f9913](https://github.com/IRsoctierDT/IANUA-Broker/commit/25f9913087c685f688adb92e26435456176d2cdd))
* **trust:** add Tier-4 agent trust analysis ([#57](https://github.com/IRsoctierDT/IANUA-Broker/issues/57)) ([d982723](https://github.com/IRsoctierDT/IANUA-Broker/commit/d982723ddb4b964587a8ed5b88226923e2dc13a0))
* Wave 1 — continuous-validation foundations (Blue Report 2026) ([#75](https://github.com/IRsoctierDT/IANUA-Broker/issues/75)) ([31cf594](https://github.com/IRsoctierDT/IANUA-Broker/commit/31cf594a174ac23a0641f14cd8f4edc98407b8e2))


### Bug Fixes

* close scan blind spots and make the test suite hermetic ([#67](https://github.com/IRsoctierDT/IANUA-Broker/issues/67)) ([f3c9a9e](https://github.com/IRsoctierDT/IANUA-Broker/commit/f3c9a9ed7af5ac1d6001036ef4091d942ef56d44))
* rename distribution to ianua-broker and repair the release-please publish gate ([#79](https://github.com/IRsoctierDT/IANUA-Broker/issues/79)) ([a0adc03](https://github.com/IRsoctierDT/IANUA-Broker/commit/a0adc0336069edf79c0312f39cee4a025175b33a))
* rename distribution to ianua-broker to match the PyPI project ([#77](https://github.com/IRsoctierDT/IANUA-Broker/issues/77)) ([c64a05d](https://github.com/IRsoctierDT/IANUA-Broker/commit/c64a05d0fcf70a973283d24a9aa9ee63871af3e2))
* **report:** make path relativization separator-agnostic (Windows CI) ([2484c99](https://github.com/IRsoctierDT/IANUA-Broker/commit/2484c99a2c16738b27e9794ffd3db9985e082c40))


### Documentation

* add CHANGELOG for v0.1.0 ([#8](https://github.com/IRsoctierDT/IANUA-Broker/issues/8)) ([729b791](https://github.com/IRsoctierDT/IANUA-Broker/commit/729b7919a1003d3c8139fc846f8a799f734b9bbf))
* add GitHub Pages landing site ([#9](https://github.com/IRsoctierDT/IANUA-Broker/issues/9)) ([ac245fc](https://github.com/IRsoctierDT/IANUA-Broker/commit/ac245fc70a9ff9649dd7923d90d5c8063df9f0b9))
* **arch:** Principal Architect validation + component design ([61a309f](https://github.com/IRsoctierDT/IANUA-Broker/commit/61a309f9581ab7b290e69353573f2b593139ef43))
* **cli:** document redaction boundary at the terminal print ([#22](https://github.com/IRsoctierDT/IANUA-Broker/issues/22)) ([6e0a3d0](https://github.com/IRsoctierDT/IANUA-Broker/commit/6e0a3d08e79c9e5771d4729e96757b1dbf4dd9fa))
* **devsecops:** add the Actions create-PRs operator setting ([#24](https://github.com/IRsoctierDT/IANUA-Broker/issues/24)) ([c71f903](https://github.com/IRsoctierDT/IANUA-Broker/commit/c71f903caa718e4f13c9c973dbdbdeee20be7ff6))
* **proposals:** add LAN-scanning and real-lab dogfood design proposals ([#35](https://github.com/IRsoctierDT/IANUA-Broker/issues/35)) ([62f9e40](https://github.com/IRsoctierDT/IANUA-Broker/commit/62f9e403ca29145ef90e0cb0182ad5250ca6e06f))
* **readme:** reflect v0.1.0 released on PyPI ([#21](https://github.com/IRsoctierDT/IANUA-Broker/issues/21)) ([d953dc0](https://github.com/IRsoctierDT/IANUA-Broker/commit/d953dc0155aae6406fec5e9d9a27d280928177d2))
* **readme:** set maturity expectation to Beta (v0.1.x) ([#20](https://github.com/IRsoctierDT/IANUA-Broker/issues/20)) ([0833884](https://github.com/IRsoctierDT/IANUA-Broker/commit/08338849f3d538e9464548de08d912da69744860))
* **review:** full-team backlog review gate (Product Council, Test, Security, Code Quality) ([9efb9dd](https://github.com/IRsoctierDT/IANUA-Broker/commit/9efb9dd507ddef191b87626b16b91eadd43beaaf))


### Miscellaneous Chores

* declare the scanner stable for the 1.0 release ([#47](https://github.com/IRsoctierDT/IANUA-Broker/issues/47)) ([4c8f28c](https://github.com/IRsoctierDT/IANUA-Broker/commit/4c8f28c3cf0f6a6cbe6077bbeae9a9e38e39fa56))

## [1.5.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v1.4.1...ai-agentic-mcpscan-v1.5.0) (2026-08-12)


### Features

* Wave 1 — continuous-validation foundations (Blue Report 2026) ([#75](https://github.com/IRsoctierDT/IANUA-Broker/issues/75)) ([31cf594](https://github.com/IRsoctierDT/IANUA-Broker/commit/31cf594a174ac23a0641f14cd8f4edc98407b8e2))

## [1.4.1](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v1.4.0...ai-agentic-mcpscan-v1.4.1) (2026-07-27)


### Bug Fixes

* close scan blind spots and make the test suite hermetic ([#67](https://github.com/IRsoctierDT/IANUA-Broker/issues/67)) ([f3c9a9e](https://github.com/IRsoctierDT/IANUA-Broker/commit/f3c9a9ed7af5ac1d6001036ef4091d942ef56d44))

## [1.4.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v1.3.0...ai-agentic-mcpscan-v1.4.0) (2026-07-12)


### Features

* **dogfood:** add Phase-2 tooling — config anonymizer and network-lab runbook ([#55](https://github.com/IRsoctierDT/IANUA-Broker/issues/55)) ([5f63052](https://github.com/IRsoctierDT/IANUA-Broker/commit/5f63052dca40cc90197add7d01802d4cff39f5f3))
* **drift:** add Tier-5 baseline + diff drift detection ([#56](https://github.com/IRsoctierDT/IANUA-Broker/issues/56)) ([77aadbd](https://github.com/IRsoctierDT/IANUA-Broker/commit/77aadbd7ddaed80b42980bce1bdc0b569ef3295b))
* **trust:** add Tier-4 agent trust analysis ([#57](https://github.com/IRsoctierDT/IANUA-Broker/issues/57)) ([d982723](https://github.com/IRsoctierDT/IANUA-Broker/commit/d982723ddb4b964587a8ed5b88226923e2dc13a0))

## [1.3.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v1.2.0...ai-agentic-mcpscan-v1.3.0) (2026-07-10)


### Features

* **lan:** SARIF logical locations for network-endpoint findings (ADR-16) ([#53](https://github.com/IRsoctierDT/IANUA-Broker/issues/53)) ([2b46434](https://github.com/IRsoctierDT/IANUA-Broker/commit/2b464342e4015c0518d1d174a7dfb61dbaec4d91))

## [1.2.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v1.1.0...ai-agentic-mcpscan-v1.2.0) (2026-07-10)


### Features

* **atlas:** add Tier-2 framework mapping command ([#51](https://github.com/IRsoctierDT/IANUA-Broker/issues/51)) ([bf7511f](https://github.com/IRsoctierDT/IANUA-Broker/commit/bf7511fe4a5fae8e0e6d9183147ce4e0b1934c46))

## [1.1.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v1.0.0...ai-agentic-mcpscan-v1.1.0) (2026-07-10)


### Features

* **inventory:** add Tier-1 AI/MCP asset inventory command ([#49](https://github.com/IRsoctierDT/IANUA-Broker/issues/49)) ([0fe0f9f](https://github.com/IRsoctierDT/IANUA-Broker/commit/0fe0f9fadddfd5d885215ba19150257ef9211309))

## [1.0.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v0.10.0...ai-agentic-mcpscan-v1.0.0) (2026-07-10)


### Miscellaneous Chores

* declare the scanner stable for the 1.0 release ([#47](https://github.com/IRsoctierDT/IANUA-Broker/issues/47)) ([4c8f28c](https://github.com/IRsoctierDT/IANUA-Broker/commit/4c8f28c3cf0f6a6cbe6077bbeae9a9e38e39fa56))

## [0.10.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v0.9.0...ai-agentic-mcpscan-v0.10.0) (2026-07-10)


### Features

* add optional [crypto] ed25519 and [yaml] Continue extras ([#43](https://github.com/IRsoctierDT/IANUA-Broker/issues/43)) ([2bdd484](https://github.com/IRsoctierDT/IANUA-Broker/commit/2bdd4847ee3511c0214808bf50e59364978d523a))
* **lan:** enterprise-policy gate for public targets + operator guide ([#42](https://github.com/IRsoctierDT/IANUA-Broker/issues/42)) ([91680fe](https://github.com/IRsoctierDT/IANUA-Broker/commit/91680fe9230a061c0e0b2b14851a988aecff5fa6))

## [0.9.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v0.8.0...ai-agentic-mcpscan-v0.9.0) (2026-07-10)


### Features

* **lan:** wire the mcpscan lan command on the safety core ([#40](https://github.com/IRsoctierDT/IANUA-Broker/issues/40)) ([44da233](https://github.com/IRsoctierDT/IANUA-Broker/commit/44da233cd858fb69faa9864be36dbc5408cd5549))

## [0.8.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v0.7.0...ai-agentic-mcpscan-v0.8.0) (2026-07-10)


### Features

* **lan:** add mcpscan lan Phase A safety core (authorization, no network) ([#38](https://github.com/IRsoctierDT/IANUA-Broker/issues/38)) ([5b661c9](https://github.com/IRsoctierDT/IANUA-Broker/commit/5b661c92aa3cf681f60e946b4c12630bdfdacb77))

## [0.7.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v0.6.0...ai-agentic-mcpscan-v0.7.0) (2026-07-10)


### Features

* **adapters:** add Zed host adapter with JSONC support ([#36](https://github.com/IRsoctierDT/IANUA-Broker/issues/36)) ([a5a87b1](https://github.com/IRsoctierDT/IANUA-Broker/commit/a5a87b1e7b2499880763c7461e95581ed5bbabc2))


### Documentation

* **proposals:** add LAN-scanning and real-lab dogfood design proposals ([#35](https://github.com/IRsoctierDT/IANUA-Broker/issues/35)) ([62f9e40](https://github.com/IRsoctierDT/IANUA-Broker/commit/62f9e403ca29145ef90e0cb0182ad5250ca6e06f))

## [0.6.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v0.5.0...ai-agentic-mcpscan-v0.6.0) (2026-07-10)


### Features

* **adapters:** add VS Code host adapter (native MCP) ([#33](https://github.com/IRsoctierDT/IANUA-Broker/issues/33)) ([4b144de](https://github.com/IRsoctierDT/IANUA-Broker/commit/4b144dea6ee9232caf6f6e8dae187917e1f57e22))

## [0.5.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v0.4.0...ai-agentic-mcpscan-v0.5.0) (2026-07-10)


### Features

* **fix:** add opt-in --fix for over-broad tool-scope grants ([#31](https://github.com/IRsoctierDT/IANUA-Broker/issues/31)) ([2fafad8](https://github.com/IRsoctierDT/IANUA-Broker/commit/2fafad80e1bc94b155c5f1c8043cea6b6707cac3))

## [0.4.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v0.3.0...ai-agentic-mcpscan-v0.4.0) (2026-07-10)


### Features

* **report:** add SARIF 2.1.0 output and code-scanning workflow ([#28](https://github.com/IRsoctierDT/IANUA-Broker/issues/28)) ([f1971c5](https://github.com/IRsoctierDT/IANUA-Broker/commit/f1971c558b6f695b27f25ec278bc7fabbf6bebcc))

## [0.3.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v0.2.0...ai-agentic-mcpscan-v0.3.0) (2026-07-08)


### Features

* **adapters:** add Windsurf and Cline host adapters ([#26](https://github.com/IRsoctierDT/IANUA-Broker/issues/26)) ([a3f9325](https://github.com/IRsoctierDT/IANUA-Broker/commit/a3f9325e2a9b45a19088896104f9330c016b2b3c))

## [0.2.0](https://github.com/IRsoctierDT/IANUA-Broker/compare/ai-agentic-mcpscan-v0.1.0...ai-agentic-mcpscan-v0.2.0) (2026-07-08)


### Features

* **adapters:** add Cursor host adapter ([#23](https://github.com/IRsoctierDT/IANUA-Broker/issues/23)) ([443b65a](https://github.com/IRsoctierDT/IANUA-Broker/commit/443b65a156dd8e0a6c8238079900b5e6d625f671))
* **sprint-1:** foundations — domain model, path resolver, safe reader, CI ([2cb9d64](https://github.com/IRsoctierDT/IANUA-Broker/commit/2cb9d641ddbe779c82ed26b4331828a7201a5647))
* **sprint-2:** core engine — discovery, Claude adapter, 4 check families, scoring ([48938ba](https://github.com/IRsoctierDT/IANUA-Broker/commit/48938bac431e3f2685a08e06d4a2653bedce2a29))
* **sprint-3:** reporting — terminal, stable JSON, self-contained HTML ([0e87f56](https://github.com/IRsoctierDT/IANUA-Broker/commit/0e87f5652e16beb9f9a1adff2854b45e8e3af97e))
* **sprint-4:** online enrichment, self-scan, security sign-off, docs ([25f9913](https://github.com/IRsoctierDT/IANUA-Broker/commit/25f9913087c685f688adb92e26435456176d2cdd))


### Bug Fixes

* **report:** make path relativization separator-agnostic (Windows CI) ([2484c99](https://github.com/IRsoctierDT/IANUA-Broker/commit/2484c99a2c16738b27e9794ffd3db9985e082c40))


### Documentation

* add CHANGELOG for v0.1.0 ([#8](https://github.com/IRsoctierDT/IANUA-Broker/issues/8)) ([729b791](https://github.com/IRsoctierDT/IANUA-Broker/commit/729b7919a1003d3c8139fc846f8a799f734b9bbf))
* add GitHub Pages landing site ([#9](https://github.com/IRsoctierDT/IANUA-Broker/issues/9)) ([ac245fc](https://github.com/IRsoctierDT/IANUA-Broker/commit/ac245fc70a9ff9649dd7923d90d5c8063df9f0b9))
* **arch:** Principal Architect validation + component design ([61a309f](https://github.com/IRsoctierDT/IANUA-Broker/commit/61a309f9581ab7b290e69353573f2b593139ef43))
* **cli:** document redaction boundary at the terminal print ([#22](https://github.com/IRsoctierDT/IANUA-Broker/issues/22)) ([6e0a3d0](https://github.com/IRsoctierDT/IANUA-Broker/commit/6e0a3d08e79c9e5771d4729e96757b1dbf4dd9fa))
* **devsecops:** add the Actions create-PRs operator setting ([#24](https://github.com/IRsoctierDT/IANUA-Broker/issues/24)) ([c71f903](https://github.com/IRsoctierDT/IANUA-Broker/commit/c71f903caa718e4f13c9c973dbdbdeee20be7ff6))
* **readme:** reflect v0.1.0 released on PyPI ([#21](https://github.com/IRsoctierDT/IANUA-Broker/issues/21)) ([d953dc0](https://github.com/IRsoctierDT/IANUA-Broker/commit/d953dc0155aae6406fec5e9d9a27d280928177d2))
* **readme:** set maturity expectation to Beta (v0.1.x) ([#20](https://github.com/IRsoctierDT/IANUA-Broker/issues/20)) ([0833884](https://github.com/IRsoctierDT/IANUA-Broker/commit/08338849f3d538e9464548de08d912da69744860))
* **review:** full-team backlog review gate (Product Council, Test, Security, Code Quality) ([9efb9dd](https://github.com/IRsoctierDT/IANUA-Broker/commit/9efb9dd507ddef191b87626b16b91eadd43beaaf))

## [0.1.0]

First public release — a local-first, offline-by-default security posture
scanner for MCP / local-agent setups (CLI: `mcpscan`).

### Added

- **CLI** — `mcpscan scan` with `--root`, `--json`, `--html`, `--online`,
  `--show-secrets`, `--absolute-paths`, and `--fail-on {critical,high,medium,low}`;
  process exit code is driven by the highest finding severity versus the
  threshold.
- **Discovery** — listening-socket enumeration via psutil (degrades gracefully
  when the OS denies introspection), a loopback-only MCP confirmation probe
  (`/mcp`, `/sse`), and declared-server discovery from Claude Code / Claude
  Desktop configs through a `HostAdapter` seam.
- **Checks (four dimensions)** — exposure (non-loopback / `0.0.0.0` binds),
  credentials (plaintext secrets by provider pattern + entropy, and secret-at-rest
  file permission / git-tracking), tool scope (auto-approved and wildcard
  permission grants), and version pinning (unpinned `npx`/`uvx`/etc.).
- **Scoring** — deterministic A–F grading per server, per dimension, and overall.
- **Reports** — ANSI terminal output, stable machine-readable JSON
  (`schema_version` "1.0"), and a self-contained, offline HTML report.
- **Online enrichment** — opt-in `--online` OSV advisory lookups for pinned
  packages; the egress module is isolated and imported only on this path.
- **Self-scan** (`mcpscan` passes its own checks) and cross-platform CI
  (macOS/Linux/Windows × Python 3.11–3.13).

### Security & trust properties

- Offline by default; no network egress unless `--online` is passed.
- Loopback-only probing — non-loopback targets are refused (fail closed).
- Secrets are reduced to fingerprints at detection; raw values never reach the
  domain model, reports, or logs. `--show-secrets` reveals only a masked form and
  prints a warning.
- No file writes except the reports you explicitly request, created `0600` where
  supported.
- Home directories are relativized to `~/…` by default (`--absolute-paths` opts
  out).

### Packaging

- Apache-2.0 licensed, with a `NOTICE` file and per-file SPDX headers.
- Publishes to PyPI via Trusted Publishing (OIDC); the version is single-sourced
  from `pyproject.toml`.

[0.1.0]: https://github.com/IRsoctierDT/IANUA-Broker/releases/tag/v0.1.0
