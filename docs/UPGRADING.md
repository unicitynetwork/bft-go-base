# Upgrade / rollout

This is the reference for rolling out the strict signature verification release (bft-go-base → bft-core →
aggregator-go). The operator procedures of the other two repositories summarise their own role and link here:

- bft-core: [docs/upgrade.md](https://github.com/unicitynetwork/bft-core/blob/uc-consolidation/docs/upgrade.md)
- aggregator-go: [README](https://github.com/unicitynetwork/aggregator-go/blob/uc-consolidation/README.md)

## Terms

- **Root validators**: the BFT Core root chain nodes. They produce and verify QCs, timeout certificates (TCs), votes,
  proposals and unicity seals.
- **Aggregators**: in this stack they are also the shard nodes. They send certification requests and verify only the
  UCs they receive (UC → unicity seal → quorum signatures) and the root trust base records. They do not verify QCs.
- **Shard validators**: a separately deployed shard consensus cohort, if there is one. It is treated according to its
  own verification paths. Normally the shard nodes are the aggregators.

## What changes

The release makes two consensus-relevant changes:

1. **Strict `VerifyHash` / `VerifyBytes`** (`crypto`): a signature must be exactly 65 bytes, `1 <= r,s < n`, low-S, with
   recovery id `v` in 0..3, and must recover to the trusted key. The old rule accepted a valid low-S ECDSA `r || s` in
   64-byte form, or in 65-byte form with the last byte ignored. The strict set is a subset of the old one: the signed
   bytes, quorum thresholds and seal/QC formats are unchanged.
2. **`ShardingScheme.IsValid` rejects incomplete schemes** (for example `{"00","01"}`). Complete schemes, the empty
   (single shard) scheme, their order and their tree commitments are unchanged. An incomplete scheme could not be
   used before either (building its shard tree never returned).

### Effect of the strict rule

`VerifyQuorumSignatures` adds up the stake of every signature that passes `VerifyBytes`. A signature that an old node
accepts and a new node rejects changes the count. Example: 4 root validators (quorum threshold 3), a seal signed by
exactly 3 of them, then one of the signatures is changed.

| change to one signature          | old rule                      | strict rule                                             |
|----------------------------------|-------------------------------|---------------------------------------------------------|
| `v ^= 2` (other recovery branch) | `seal.Verify(tb)` returns nil | `quorum not reached, signed_votes=2 quorum_threshold=3` |
| `v = 27`                         | nil                           | quorum not reached                                      |
| truncated to 64 bytes            | nil                           | quorum not reached                                      |

- **Liveness, not a fork.** The old rule accepts a superset of what the strict rule accepts, and both need a quorum of
  real root keys. Mixed rules can therefore disagree about whether a seal or QC has a quorum, and *can* stall
  progress, but this alone does not make two conflicting states final.
- **Only a non-strict signature causes it.** If every signature is strict, a mixed network behaves as before.
  Non-strict signatures come from a Byzantine signer, or from anyone who relays a signature and changes its recovery
  byte or strips it (no private key needed; the signed bytes do not include the signature map).
- **Honest signers are unaffected.** Every signing path in bft-core and aggregator-go uses the in-memory signer, which
  produces 65-byte, low-S signatures with `v` in {0,1}. No key or signing-code change is needed.
- **Affected paths:** seals, QCs, timeout certificates, votes and proposals, certification requests and the signatures
  of root trust base records. Aggregators are affected through seals and trust base records only.

## Baseline assumption: stop-all upgrade

The current binaries have **no activation gate**, no version negotiation and no per-epoch switch. The conservative
baseline for this release is therefore a stop-all upgrade: stop every process, upgrade, restart. This is an assumption
about what is known to be safe, not a requirement: a gentler procedure is fine where it is simple and safe, and the
next section describes the one recommended.

## Gentler procedure: coordinated validator cutover, then rolling aggregators

1. **Cut over all root validators together** (and a shard consensus cohort per its own verification paths). A
   rolling upgrade *inside* the validator cohort is not supported: consensus must not mix verification rules.
   New certifications pause during the cutover; do not promise uninterrupted writes (quiesce submissions, or let the
   aggregators hold their pending block and resend it when the root is back).
2. **Keep the aggregators running** and upgrade them afterwards, one by one, keeping each shard available. Strict-valid
   certificates pass the old verifier, and aggregators already send strict-valid requests. An old aggregator keeps the
   old (wider) acceptance until it is upgraded; its acceptance of certificates may differ from upgraded nodes until then.
3. **Not the reverse order.** Strict aggregators with legacy validators can reject a seal that the root finalized,
   which stops that shard's progress and proof service.

This assumes that the wire and storage formats of the other changes in the release are compatible (check separately),
and it **needs a deployment rehearsal before it is advertised as a tested procedure.**

### Preflight and constraints

- Verify the durable artifacts under the strict rule on copies of real state: QCs, TCs, UCs/seals, root trust base
  history, snapshots and persisted proofs. Stopping every process does not make legacy-only artifacts strict-valid.
  If any is found, stop and resolve it explicitly (fetch a strict-valid certificate for the same commitment, or agree a
  historical compatibility plan). Do not rewrite certificates, lower the quorum or delete history.
- Check the node keys of the trust base and the complete sharding schemes (incomplete schemes are now rejected).
- Back up durable state. **Never erase safety (anti-equivocation) records** to make a restart succeed.
- Fence the old validators so that none rejoins after the cutover.
- After the cutover, check quorum progress, recovery and fresh UC production, and that a still-old aggregator
  processes the UCs, before upgrading the aggregators.
- Rollback after new progress needs a coordinated, state-compatible plan: do not restart isolated old binaries or
  restore stale signing state.

## Future work

A fully rolling validator upgrade (a compatibility release that keeps the old rule below an authenticated activation
epoch, then strict from that epoch) is possible, but is not implemented.

## Merge order

bft-go-base → bft-core → aggregator-go. bft-core must also take the `leaderNode.NodeID` formatting fix
(bft-core#38) together with this dependency, since `go vet` rejects the old code.
