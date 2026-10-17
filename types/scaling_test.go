package types

import (
	"bytes"
	"crypto"
	"math"
	"math/big"
	"math/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// randomCompleteScheme splits random leaves until the scheme has n shards (complete, prefix-free, canonical not guaranteed).
func randomCompleteScheme(rng *rand.Rand, n int) ShardingScheme {
	leaves := []ShardID{{}}
	for len(leaves) < n {
		i := rng.Intn(len(leaves))
		a, b := leaves[i].Split()
		leaves[i] = a
		leaves = append(leaves, b)
	}
	return leaves
}

// caterpillarScheme is the maximally unbalanced complete scheme: 0, 10, 110, ... (depth n-1).
func caterpillarScheme(n int) ShardingScheme {
	var s ShardingScheme
	cur := ShardID{}
	for len(s) < n-1 {
		a, b := cur.Split()
		s = append(s, a)
		cur = b
	}
	return append(s, cur)
}

func canonicalSorted(s ShardingScheme) ShardingScheme {
	c := slices.Clone(s)
	slices.SortFunc(c, compareShardIDs)
	return c
}

// referenceIsValid is the previous O(S^2) pairwise definition (plus the Kraft sum completeness check, an independent
// model of what checkComplete does): the slow reference model.
func referenceIsValid(sh ShardingScheme) (ok bool, pairs int) {
	if len(sh) == 1 {
		return false, 0
	}
	for idxA, idA := range sh {
		if idA.length == 0 {
			return false, pairs
		}
		isPrefixOf := idA.Comparator()
		for idxB, idB := range sh {
			pairs++
			if idA.length <= idB.length && idxA != idxB && isPrefixOf(idB.bits) {
				return false, pairs
			}
		}
	}
	// prefix-free scheme covers the whole tree iff the Kraft sum equals one
	maxLen := uint(0)
	for _, id := range sh {
		maxLen = max(maxLen, id.length)
	}
	sum := new(big.Int)
	for _, id := range sh {
		sum.Add(sum, new(big.Int).Lsh(big.NewInt(1), maxLen-id.length))
	}
	if len(sh) > 0 && sum.Cmp(new(big.Int).Lsh(big.NewInt(1), maxLen)) != 0 {
		return false, pairs
	}
	return true, pairs
}

func countingCmp(n *int) func(a, b ShardID) int {
	return func(a, b ShardID) int { *n++; return compareShardIDs(a, b) }
}

// The new validation agrees with the reference model on valid and adversarial schemes in any order.
func TestShardingSchemeIsValid_MatchesReferenceModel(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 2000; iter++ {
		s := randomCompleteScheme(rng, 2+rng.Intn(40))
		switch rng.Intn(8) {
		case 1: // duplicate
			s = append(s, s[rng.Intn(len(s))])
		case 2: // a prefix of an existing shard
			id := s[rng.Intn(len(s))]
			if id.length > 1 {
				p := ShardID{bits: slices.Clone(id.bits), length: id.length - 1}
				if p.length%8 != 0 {
					p.bits[len(p.bits)-1] &= byte(0xFF << (8 - p.length%8))
				} else {
					p.bits = p.bits[:p.length/8]
				}
				s = append(s, p)
			}
		case 3: // an extension of an existing shard
			a, _ := s[rng.Intn(len(s))].Split()
			s = append(s, a)
		case 4: // empty ID
			s = append(s, ShardID{})
		case 5: // single
			s = s[:1]
		case 6: // a missing shard
			i := rng.Intn(len(s))
			s = append(slices.Clone(s[:i]), s[i+1:]...)
		case 7: // a shard of the complete scheme replaced by one of its two halves
			i := rng.Intn(len(s))
			s[i], _ = s[i].Split()
		}
		rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
		want, _ := referenceIsValid(s)
		require.Equal(t, want, s.IsValid() == nil, "scheme %v", s)
		if want {
			require.True(t, slices.IsSortedFunc(canonicalSorted(s), compareShardIDs))
		}
	}
}

// compareShardIDs is exactly the left-to-right bit string order (the old canonical order).
func TestCompareShardIDs_IsBitStringOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	s := randomCompleteScheme(rng, 300)
	got := canonicalSorted(s)
	want := slices.Clone(s)
	slices.SortFunc(want, func(a, b ShardID) int { return bytes.Compare([]byte(a.String()), []byte(b.String())) })
	require.Equal(t, want, got)
}

// Validation work is counted in shard ID comparisons: linear for canonical input, S log S otherwise;
// the reference pair count is quadratic.
func TestShardingSchemeValidation_CountedWork(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	sizes := []int{16, 32, 64, 128, 256, 512, 1024}
	schemes := map[string]func(n int) ShardingScheme{
		"balanced-canonical": func(n int) ShardingScheme { return canonicalSorted(randomCompleteScheme(rng, n)) },
		"random-shuffled": func(n int) ShardingScheme {
			s := randomCompleteScheme(rng, n)
			rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
			return s
		},
		"caterpillar-canonical": func(n int) ShardingScheme { return canonicalSorted(caterpillarScheme(n)) },
	}
	for name, gen := range schemes {
		t.Run(name, func(t *testing.T) {
			var prev, prevRef int
			for _, n := range sizes {
				s := gen(n)
				var cmps int
				_, err := s.sortedValid(countingCmp(&cmps))
				require.NoError(t, err)
				ok, pairs := referenceIsValid(s)
				require.True(t, ok)
				if name != "random-shuffled" {
					require.LessOrEqual(t, cmps, n, "canonical input must validate with <= S comparisons")
				} else {
					require.LessOrEqual(t, float64(cmps), 2*float64(n)*math.Log2(float64(n))+float64(n))
				}
				require.GreaterOrEqual(t, pairs, n*(n-1)/2/2) // reference grows quadratically
				if prev != 0 {
					// doubling S: new work at most ~3x (S log S), reference ~4x
					require.LessOrEqual(t, float64(cmps), 3.0*float64(prev), "n=%d", n)
					require.GreaterOrEqual(t, float64(pairs), 3.0*float64(prevRef))
				}
				prev, prevRef = cmps, pairs
			}
		})
	}
}

// CanonicalShardOrder (scheme validation + order) sorts at most once and agrees with the old order.
func TestCanonicalShardOrder_SingleSortCounted(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	var prev int
	for _, n := range []int{64, 128, 256, 512, 1024} {
		s := randomCompleteScheme(rng, n)
		rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
		var cmps int
		got, err := canonicalShardOrder(s, countingCmp(&cmps))
		require.NoError(t, err)
		require.Equal(t, []ShardID(canonicalSorted(s)), got)
		require.LessOrEqual(t, float64(cmps), 2*float64(n)*math.Log2(float64(n))+float64(n))
		if prev != 0 {
			require.LessOrEqual(t, float64(cmps), 3.0*float64(prev))
		}
		prev = cmps
	}
	// the scheme itself is not modified
	s := randomCompleteScheme(rng, 32)
	rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
	before := slices.Clone(s)
	require.False(t, slices.IsSortedFunc(s, compareShardIDs), "the input must be unsorted so that the sorting path runs")
	got, err := canonicalShardOrder(s, compareShardIDs) // the public function caps the scheme at 8 shards
	require.NoError(t, err)
	require.True(t, slices.IsSortedFunc(got, compareShardIDs))
	require.Equal(t, before, s, "the caller's scheme must not be reordered")
	// the public function does not modify an (8 shard, unsorted) scheme either
	small := randomCompleteScheme(rng, 8)
	for slices.IsSortedFunc(small, compareShardIDs) {
		rng.Shuffle(len(small), func(i, j int) { small[i], small[j] = small[j], small[i] })
	}
	smallBefore := slices.Clone(small)
	_, err = CanonicalShardOrder(small)
	require.NoError(t, err)
	require.Equal(t, smallBefore, small)
}

// Lazy per-shard certificate derivation from the one authenticated tree: leaf lookups are one index probe
// (counted) and the allocations of one derivation grow with the tree depth, not with the number of shards.
func TestAuthenticatedView_LazyCertificateWorkIndependentOfS(t *testing.T) {
	build := func(n int) *AuthenticatedPartitionView {
		scheme := canonicalSorted(randomCompleteScheme(rand.New(rand.NewSource(int64(n))), n))
		view := &PartitionViewV1{PartitionID: pvTestPartition}
		var inputs []ShardTreeInput
		for _, id := range scheme {
			ir := &InputRecord{Version: 1, Hash: bytes.Repeat([]byte{1}, 32), SummaryValue: []byte{1}}
			trh, ch := bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
			view.Leaves = append(view.Leaves, PartitionViewLeafV1{ShardID: id, InputRecord: ir, TRHash: trh, ShardConfHash: ch})
			inputs = append(inputs, ShardTreeInput{Shard: id, IR: ir, TRHash: trh, ShardConfHash: ch})
		}
		tree, err := CreateShardTree(scheme, inputs, crypto.SHA256)
		require.NoError(t, err)
		seal := &UnicitySeal{Version: 1, Hash: tree.RootHash()}
		sb, err := seal.MarshalCBOR()
		require.NoError(t, err)
		pb, err := (&UnicityTreeCertificate{Version: 1, Partition: pvTestPartition}).MarshalCBOR()
		require.NoError(t, err)
		return &AuthenticatedPartitionView{partition: pvTestPartition, view: view, tree: tree, index: leafIndex(view), sealBytes: sb, pathBytes: pb}
	}
	var base float64
	for _, n := range []int{16, 64, 256, 1024, 4096} {
		av := build(n)
		id := av.view.Leaves[n-1].ShardID // last leaf: worst case for a linear scan
		var probes int
		av.onProbe = func() { probes++ }
		const lookups = 5
		for i := 0; i < lookups; i++ {
			_, err := av.Certificate(id)
			require.NoError(t, err)
			_, ok := av.ShardConfHash(id)
			require.True(t, ok)
		}
		// exactly one index probe per lookup whatever S is (a linear scan of the last leaf would examine S)
		require.Equal(t, 2*lookups, probes, "S=%d", n)
		av.onProbe = nil // the allocation count below is of the production path
		allocs := testing.AllocsPerRun(20, func() {
			_, err := av.Certificate(id)
			require.NoError(t, err)
			_, ok := av.ShardConfHash(id)
			require.True(t, ok)
		})
		if base == 0 {
			base = allocs
		}
		// depth grows ~ log2 S (x3 from S=16 to 4096): allow depth-proportional growth only (never S-proportional)
		require.LessOrEqual(t, allocs, base*3+10, "S=%d allocs=%v base=%v", n, allocs, base)
	}
}
