# Third-Party Licenses

AI Agentic MCPscan is licensed under the Apache License 2.0 (see
[`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE)). This file records the
licenses of the third-party software it depends on.

The runtime dependency surface is intentionally minimal (see
`docs/SECURITY_SIGNOFF.md`): one required package, plus two optional extras.
Development-only tools (pytest, ruff, mypy, bandit, pip-audit, build) are not
distributed with the package and are therefore not inventoried here; a full
machine-readable SBOM (CycloneDX) is produced per release by the `sbom` CI
workflow.

| Package | Version policy | License | Used for |
|---|---|---|---|
| [psutil](https://github.com/giampaolo/psutil) | `>=5.9` (required) | [BSD-3-Clause](https://github.com/giampaolo/psutil/blob/master/LICENSE) | Listening-socket / process enumeration for the exposure checks |
| [cryptography](https://github.com/pyca/cryptography) | optional `[crypto]` extra | [Apache-2.0 OR BSD-3-Clause](https://github.com/pyca/cryptography/blob/main/LICENSE) | ed25519 manifest signature verification for `mcpscan lan` |
| [PyYAML](https://github.com/yaml/pyyaml) | optional `[yaml]` extra | [MIT](https://github.com/yaml/pyyaml/blob/main/LICENSE) | Parsing Continue's `config.yaml` in the Continue host adapter |

Each package's full license text — including its required copyright notice —
ships inside the package's own distribution (`*.dist-info/`) and is therefore
retained verbatim in any installed or redistributed environment, satisfying the
notice-retention conditions of these licenses. The links above point to the
authoritative upstream texts.
