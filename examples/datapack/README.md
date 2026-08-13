# Example detection data-pack

`example-datapack.json` is the built-in IANUA-Broker catalog **plus one extra
provider pattern** — an `"Acme deploy token"` matching `acme-[0-9]{10}` — as a
concrete starting point for your own org-specific detections.

It is intentionally **unsigned**: a pack is only trusted when signed by a key in
*your* allowed-signers file, so sign it with your own key rather than shipping a
signature anyone could reproduce. The full flow (author → sign → install) is in
[`docs/DATAPACK.md`](../../docs/DATAPACK.md).

Quick verify-and-install with a throwaway key:

```bash
# sign under the datapack namespace
ssh-keygen -Y sign -n mcpscan-datapack -f ~/.ssh/id_ed25519 example-datapack.json
echo "you@example.com $(cat ~/.ssh/id_ed25519.pub)" > allowed-signers

mcpscan update-datapack \
  --pack example-datapack.json \
  --signature example-datapack.json.sig \
  --allowed-signers allowed-signers \
  --signer you@example.com

# a config holding `acme-1234567890` is now flagged as a plaintext Acme deploy token
```
