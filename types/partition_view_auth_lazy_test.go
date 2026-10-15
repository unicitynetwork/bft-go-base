package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// Deriving the certificate of one shard costs one indexed lookup, not a scan of the view:
// the probes of deriving every shard are S (not S(S+1)/2), and each derived certificate equals
// the eager reference derivation.
func Test_AuthenticatedPartitionView_LazyCertificateIsIndexed(t *testing.T) {
	for _, bits := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("%d shards", 1<<bits), func(t *testing.T) {
			scheme := pvScheme(bits)
			f := pvEnclose(t, pvView(t, scheme), pvTopology(scheme))
			av, err := pvAuth(f)
			require.NoError(t, err)
			eager, err := av.Certificates()
			require.NoError(t, err)
			order, err := CanonicalShardOrder(scheme)
			require.NoError(t, err)

			before := av.leafProbes.Load()
			for i, id := range order {
				got, err := av.Certificate(id)
				require.NoError(t, err)
				want, err := eager[i].MarshalCBOR()
				require.NoError(t, err)
				have, err := got.MarshalCBOR()
				require.NoError(t, err)
				require.Equal(t, want, have, "shard %q", id)
			}
			require.EqualValues(t, len(order), av.leafProbes.Load()-before, "one probe per derivation")

			deep := ShardID{}
			for range 5 { // deeper than any shard of the scheme
				deep, _ = deep.Split()
			}
			_, err = av.Certificate(deep)
			require.Error(t, err)
		})
	}
}
