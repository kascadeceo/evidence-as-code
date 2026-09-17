# Synthetic evidence bundle

This bundle contains invented data for learning and testing. It does not describe a real organization, account, or cloud resource.

Verify it from the repository root:

```bash
python verify.py examples/evidence-bundle
```

The command prints `VERIFIED` and exits 0. Now make a disposable copy and alter one byte:

```bash
cp -r examples/evidence-bundle /tmp/b
echo >> /tmp/b/ssp.md
python verify.py /tmp/b
```

The second verification prints `artifact_altered` and exits 1. Each ledger entry hashes its own contents and points to the stored digest of the previous entry, so silently changing an old record breaks either that record's digest or the next link. The latest entry also records the expected bytes for each current artifact.
