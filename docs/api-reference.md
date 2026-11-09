# Go Base API Reference

## Trust-base entries and bundles

The `types` package provides the V2 entry codec, predecessor verification, GetTrustBase page codec and complete history bundles. It does not provide a release pin table, HTTP fetch loop, cached session or persistent history store; consumers own those policies.

### Authenticate a complete bundle

A complete bundle is a tag-39015 GetTrustBase response containing every entry from genesis to its stated tip, status OK and no continuation. Supply an independently authenticated genesis EntryID and the expected network, rather than deriving authority from the downloaded bytes:

```go
import (
    "fmt"
    "github.com/unicitynetwork/bft-go-base/types"
)

func authenticateBundle(data []byte, expectedNetwork types.NetworkID,
    genesisID [types.TrustBaseV2IDLen]byte) (*types.TrustBaseBundle, error) {
    bundle, err := types.DecodeTrustBaseBundle(data, types.TrustBaseLimits{
        MaxBytes: 16 << 20, MaxEntries: 4096, // Application resource budget.
    })
    if err != nil {
        return nil, err
    }
    if bundle.Network != expectedNetwork {
        return nil, fmt.Errorf("unexpected trust-base network %d", bundle.Network)
    }
    if err := types.VerifyTrustBaseBundle(bundle, genesisID); err != nil {
        return nil, err
    }
    return bundle, nil
}
```

Use the same flow for mainnet (network 1), testnet2 (4), or a private network, with that network's authenticated configuration. This library does not select public pins for you. Keep the verified history for old certificates; a newer authority does not retroactively verify older epochs.

### Entries and signature verification

| API in `types` | Contract |
| --- | --- |
| `DecodeRootTrustBaseV2(data)` | Strict deterministic tag-39000/version-2 decode and structural validation; not signature verification. |
| `RootTrustBaseV2.MarshalCBOR()` / `SigBytes()` | Encode the complete entry / unsigned entry with a null signature field. |
| `EntryID()` | SHA-256 of `SigBytes()`, independent of which valid signature witnesses are supplied. |
| `VerifyGenesis()` | Check genesis structure, including zero predecessor and null signatures; caller must still compare the EntryID to a trusted pin. |
| `VerifySuccessor(previous)` | Check network, next epoch, increasing start round, predecessor EntryID and the predecessor committee's weighted quorum. `previous` must already be authenticated. |
| `EncodeTrustBaseBundle(rawEntries)` | Package canonical entries in ascending order, rejecting gaps/broken links; does not authenticate signatures. |
| `DecodeTrustBaseBundle(data, limits)` / `VerifyTrustBaseBundle(bundle, pin)` | Decode complete structure/links, then separately authenticate genesis and every successor. Pass a successfully decoded bundle to the verifier. |

Entry quorum is `floor(2 * totalWeight / 3) + 1`. Every supplied entry signature must belong to a member and be valid: exactly 65 bytes, low-S and recovery to that member's key. Unknown or bad extras reject the entry even if other signatures reach quorum. This strict entry rule is separate from the seal-signature counting rule. `RootTrustBaseV2` is mutable Go data; do not modify entries after validating them or publishing them to consumers.

### Pages, limits and errors

`DecodeTrustBaseResponse(data, types.TrustBasePageLimits)` returns the response plus decoded entries. The response is tag 39015, `[version=1, network, status, fromEpoch, effectiveEnd, endEntryID|null, entries, nextEpoch|null]`; this envelope version is distinct from entry version 2. The decoder checks deterministic encoding, structure, contiguous epochs and links, not signature authority or the caller's expected network.

Consumers must compare the network, authenticate each new entry from their held predecessor and keep any previously held entry immutable. For paging, retain the first response's end epoch/EntryID and require subsequent pages to use that same snapshot. A page without a cursor is not necessarily a complete genesis-to-tip bundle. Non-OK statuses carry no entries/cursor; a server reporting no newer entry is not authenticated freshness. Transport retries and refusal handling belong to the caller.

| Resource | Bound |
| --- | --- |
| Entry members / node identifier | 256 / 128 UTF-8 bytes |
| One member's weight | 1 through 2^40 |
| Page (`TrustBasePageLimits`) | 64 entries / 1 MiB |
| Entry inside a decoded page/bundle (`MaxTrustBaseEntryBytes`) | 128 KiB |
| Complete bundle | Caller-supplied positive `TrustBaseLimits`; no fixed history length |

The stand-alone entry decoder has structural CBOR bounds; callers reading untrusted raw entry bytes should enforce the 128 KiB entry budget before decoding, as the page/bundle decoder does. The shared maximum-entry fixture (256 members, 128-byte IDs and 256 signatures) is 95,365 bytes. These are resource limits, not deployment committee recommendations.

Use `errors.Is` with `ErrTrustBaseV2Encoding`, `ErrTrustBaseV2Invalid`, `ErrTrustBaseV2Signature` and `ErrTrustBaseV2Chain` for entry failures, and `ErrTrustBaseResponseEncoding`, `ErrTrustBaseResponse`, `ErrTrustBaseBundle`, `ErrTrustBaseBundleChain` for page/bundle failures. Decode success alone must never authorize a trust-base replacement.

Source: [entries](../types/root_trust_base_v2.go), [responses](../types/trust_base_response.go), [bundles](../types/trust_base_bundle.go). Interoperability fixtures live under `testdata/trust-base-v2`, `testdata/trust-base-response` and `testdata/trust-base-v2/max-entry`; consult the tracked testdata directories for their versioned layouts.
