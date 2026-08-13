# Detection data-packs — authoring, signing, installing

A **data-pack** is a signed, opt-in refresh of IANUA-Broker's detection catalogs
between releases: the secret-provider patterns, the secret-name regex and entropy
thresholds, the agent-marker list, and the token-store path templates. It exists
so a team can add org-specific detections (an internal token shape, a private
agent host) without waiting for a release — while keeping the scanner's
**verify-or-refuse, offline** guarantees.

Trust properties (identical to `mcpscan lan`):

- **Verify-or-refuse.** A pack is used only if a detached signature over its
  exact bytes verifies against an allowed-signers file. A bad or absent
  signature is **refused** — the scanner silently falls back to its built-in
  catalog, never a half-trusted pack.
- **Offline.** `update-datapack` contacts **no network**; it verifies a local
  file and installs it to a local store. There is no auto-fetch.
- **Domain-separated.** Pack signatures use the `mcpscan-datapack` namespace
  (SSH) or a datapack context prefix (ed25519), so a signature minted for
  `mcpscan lan` can never cross-verify as a pack, and vice-versa.
- **Owner-only at rest.** The installed store is written `0600`.

The store location is `$XDG_CONFIG_HOME/mcpscan/datapack.json` (falling back to
`~/.config/mcpscan/datapack.json`) on POSIX, and `%APPDATA%\mcpscan\datapack.json`
on Windows. With no pack installed, behavior is **byte-identical** to the
built-in catalog.

## 1. Author a pack

Start from the built-in catalog and extend it — the pack is a superset, so your
detections add to (never replace) the shipped ones:

```python
from dataclasses import replace
from mcpscan.datapack import builtin_datapack, datapack_to_json

base = builtin_datapack()
pack = replace(
    base,
    # add an org-specific provider pattern (label, regex)
    provider_patterns=base.provider_patterns + (("Acme deploy token", r"acme-[0-9]{10}"),),
    # and/or an org agent-host marker
    agent_markers=base.agent_markers + ("acmeagent",),
)
open("example-datapack.json", "w").write(datapack_to_json(pack))
```

A ready-made sample is in [`examples/datapack/`](../examples/datapack/). The pack
is validated on load (bad regex, non-finite thresholds, empty markers, etc. are
refused), so a malformed pack can never weaken detection silently.

## 2. Sign it

### SSH scheme (default, dependency-free)

```bash
# sign the exact pack bytes under the datapack namespace
ssh-keygen -Y sign -n mcpscan-datapack -f ~/.ssh/id_ed25519 example-datapack.json
# -> writes example-datapack.json.sig

# publish the signer identity + public key as an allowed-signers file
echo "you@example.com $(cat ~/.ssh/id_ed25519.pub)" > allowed-signers
```

### ed25519 scheme (the `[crypto]` extra)

Sign the datapack context prefix concatenated with the pack bytes
(`b"mcpscan-datapack\x00" + pack_bytes`), base64-encode the raw signature into
`<pack>.sig`, and list the operator's raw public key (base64) in the
allowed-signers file. Install with `--scheme ed25519`. (The SSH scheme needs no
extra and is recommended.)

## 3. Install it

```bash
mcpscan update-datapack \
  --pack example-datapack.json \
  --signature example-datapack.json.sig \
  --allowed-signers allowed-signers \
  --signer you@example.com
```

On success the pack is verified and installed to the local store (the command
prints the path and discloses that no network was contacted). On a bad signature
nothing is installed and the command exits non-zero. Every later `mcpscan scan`
then applies the pack's catalogs — e.g. a config holding `acme-1234567890` under
the sample pack is flagged as a plaintext **Acme deploy token**.

To revert, delete the store file; the scanner falls straight back to its
built-in catalog.

## 4. Distributing to a team

Ship the pack + its `.sig` + the `allowed-signers` file (public keys only — never
a private key) through your normal channel (an internal repo, an MDM push). Each
machine runs the `update-datapack` command above. Because verification is local
and offline, distribution is just moving three public files; trust is anchored in
the allowed-signers you control.
