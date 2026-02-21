# Snapshot Alignment Toolkit

This folder provides a concrete config baseline to keep Snapshot space settings aligned with on-chain governance contracts.

## Files

- `snapshot/space-settings.example.json`
  - Snapshot space settings template using a stake-based `contract-call` strategy.
- `snapshot/governance-manifest.schema.json`
  - JSON schema for governance alignment metadata.
- `snapshot/governance.manifest.example.json`
  - Example manifest instance with contract wiring + threshold expectations.

## Workflow

1. Copy `snapshot/governance.manifest.example.json` to `snapshot/governance.manifest.json`.
2. Fill deployed contract addresses and expected governance/oracle parameters.
3. Keep `snapshot.space` and `snapshot.spaceHash` in sync (`spaceHash` must be `keccak256(space)`).
4. Set `snapshot.configHash` from the manifest config digest produced by the checker.
5. Commit the same hash on-chain using `ParameterManager.setSnapshotConfigHash(bytes32)` via governance execution.
6. Configure your Snapshot space with `snapshot/space-settings.example.json` as the baseline.
7. Run the checker script against your RPC:

```bash
node script/check-snapshot-manifest.mjs snapshot/governance.manifest.json --rpc-url "$RPC_URL"
```

8. Generate governance calldata for committing `snapshot.configHash`:

```bash
node script/build-snapshot-config-calldata.mjs snapshot/governance.manifest.json
```

Use the emitted `{ target, value, data }` object inside the Snapshot proposal transaction bundle.

The checker fails if any critical alignment invariant is violated.
