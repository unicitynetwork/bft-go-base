package types

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"iter"
	"slices"

	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type ShardID struct {
	bits []byte
	// length is shard ID length in bits.
	length uint
}

// Length returns shard ID length in bits.
func (id ShardID) Length() uint { return id.length }

// Bytes returns binary serialization of the shard ID suitable for hashing
func (id ShardID) Bytes() []byte {
	return encodeBitstring(id.bits, id.length)
}

/*
Key is intended to be used where comparable shard ID is needed (ie map key).
*/
func (id ShardID) Key() string {
	return string(id.Bytes())
}

func (id ShardID) AddToHasher(h abhash.Hasher) {
	h.Write(id)
}

func (id ShardID) String() (s string) {
	byteCnt := id.length / 8
	for i := uint(0); i < byteCnt; i++ {
		s += fmt.Sprintf("%08b", id.bits[i])
	}
	if b := id.length % 8; b > 0 {
		s += fmt.Sprintf("%08b", id.bits[byteCnt])[:b]
	}
	return s
}

/*
Split increases shard ID length by one bit and returns the two new IDs.
The original shard ID is not altered.
*/
func (id ShardID) Split() (ShardID, ShardID) {
	bitCnt := id.length + 1
	if id.length%8 == 0 {
		return ShardID{bits: append(slices.Clone(id.bits), 0), length: bitCnt},
			ShardID{bits: append(slices.Clone(id.bits), 128), length: bitCnt}
	}

	b1 := slices.Clone(id.bits)
	b1[len(b1)-1] |= 1 << (7 - id.length%8)
	return ShardID{bits: slices.Clone(id.bits), length: bitCnt},
		ShardID{bits: b1, length: bitCnt}
}

func (id ShardID) Equal(v ShardID) bool {
	return id.length == v.length && bytes.Equal(id.bits, v.bits)
}

/*
Comparator returns function which checks does the byte slice argument
have the prefix which matches the shard ID.
NB! It is callers responsibility to not pass shorter slice than the shard id!
*/
func (id ShardID) Comparator() func([]byte) bool {
	switch {
	case id.length == 0:
		return func(b []byte) bool { return true }
	case id.length <= 8:
		mask := byte(0xFF << (8 - id.length))
		return func(b []byte) bool { return b[0]&mask == id.bits[0] }
	case id.length <= 16:
		sid := uint16(id.bits[0])<<8 | uint16(id.bits[1])
		mask := uint16(0xFFFF << (16 - id.length))
		return func(b []byte) bool {
			_ = b[1]
			v := uint16(b[0])<<8 | uint16(b[1])
			return v&mask == sid
		}
	default:
		byteCnt, bitCnt := id.length/8, id.length%8
		mask := byte(0xFF << (8 - bitCnt))
		return func(b []byte) bool {
			return bytes.HasPrefix(b, id.bits[:byteCnt]) && (bitCnt == 0 || b[byteCnt]&mask == id.bits[byteCnt])
		}
	}
}

func (id ShardID) MarshalText() ([]byte, error) {
	return hex.Encode(encodeBitstring(id.bits, id.length)), nil
}

func (id *ShardID) UnmarshalText(src []byte) error {
	res, err := hex.Decode(src)
	if err != nil {
		return fmt.Errorf("decoding from hex: %w", err)
	}
	if id.bits, id.length, err = decodeBitstring(res); err != nil {
		return fmt.Errorf("decoding bitstring: %w", err)
	}
	// some tests use "deep equal" comparison and it will break if we
	// use empty slice instead of nil (as the ShardID zero value does, but
	// decodeBitstring returns empty non nil slice for zero length bit string)
	if id.length == 0 && id.bits != nil {
		id.bits = nil
	}
	return nil
}

func (id ShardID) MarshalCBOR() ([]byte, error) {
	return Cbor.Marshal(id.Bytes())
}

func (id *ShardID) UnmarshalCBOR(data []byte) (err error) {
	var b []byte
	if err := Cbor.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("decoding bitstring bytes from CBOR: %w", err)
	}
	if id.bits, id.length, err = decodeBitstring(b); err != nil {
		return fmt.Errorf("decoding bitstring: %w", err)
	}
	// some tests use "deep equal" comparison and it will break if we
	// use empty slice instead of nil (as the ShardID zero value does, but
	// decodeBitstring returns empty non nil slice for zero length bit string)
	if id.length == 0 && id.bits != nil {
		id.bits = nil
	}
	return nil
}

type ShardingScheme []ShardID

/*
All returns iterator over all shard IDs in the sharding scheme.

For a single shard scheme (empty list) single empty shard ID is returned.
*/
func (sh ShardingScheme) All() iter.Seq[ShardID] {
	if len(sh) == 0 {
		return func(yield func(ShardID) bool) { yield(ShardID{}) }
	}

	return func(yield func(ShardID) bool) {
		for _, id := range sh {
			if !yield(id) {
				return
			}
		}
	}
}

// compareShardIDs orders shard IDs as bit strings, "0" before "1", a proper prefix before its
// extensions. Unused bits of ShardID.bits are always zero, so comparing the padded bytes first and
// the lengths second is exactly the bit string order.
func compareShardIDs(a, b ShardID) int {
	if c := bytes.Compare(a.bits, b.bits); c != 0 {
		return c
	}
	return cmp.Compare(a.length, b.length)
}

// IsValid checks that the scheme is a non-trivial, prefix-free and complete set of non-empty shard IDs
// (the empty scheme denotes a single shard and is valid). Complete means that the shard IDs cover the whole
// shard tree: every bit string is prefixed by exactly one shard ID. An incomplete scheme such as {"00", "01"}
// is rejected, as building a shard tree for it can't terminate.
//
// In bit string order every extension of a shard ID A sorts directly after A, so a scheme is prefix-free
// (and duplicate-free) iff no ID is a prefix of its successor. That is O(S) comparisons for an already
// canonical (sorted) scheme and O(S log S) otherwise, instead of the O(S^2) pairwise check.
func (sh ShardingScheme) IsValid() error {
	_, err := sh.sortedValid(compareShardIDs)
	return err
}

// sortedValid validates the scheme and returns it in bit string order. The input is not modified;
// it is only copied when it is not already sorted. cmp is the (counted in tests) order.
func (sh ShardingScheme) sortedValid(cmp func(a, b ShardID) int) (ShardingScheme, error) {
	// single shard scheme is denoted by empty slice, there is no valid case with single item
	if len(sh) == 1 {
		return nil, fmt.Errorf("scheme can't contain single shard, got %q", sh[0])
	}
	sorted := true
	for i := range sh {
		if sh[i].length == 0 {
			return nil, errors.New("scheme may not contain empty shard ID")
		}
		if i > 0 && cmp(sh[i-1], sh[i]) > 0 {
			sorted = false
		}
	}
	ordered := sh
	if !sorted {
		ordered = slices.Clone(sh)
		slices.SortFunc(ordered, cmp)
	}
	for i := 1; i < len(ordered); i++ {
		a, b := ordered[i-1], ordered[i]
		if a.length <= b.length && a.Comparator()(b.bits) {
			return nil, fmt.Errorf("scheme is not prefix-free: %s is prefix of %s", a, b)
		}
	}
	if err := checkComplete(ordered); err != nil {
		return nil, err
	}
	return ordered, nil
}

// checkComplete checks that a non-empty, prefix-free scheme in bit string order covers the whole shard tree.
//
// Read a shard ID as the interval [x, x+2^-len) of [0,1), where x is the ID as a binary fraction. A prefix-free scheme
// covers the tree iff the intervals in order tile [0,1): the first one starts at 0, each one starts where the previous
// one ends, and the last one ends at 1. The end of shard ID A is A+1 (as a len(A)-bit integer), and as unused bits of
// ShardID.bits are zero, "starts at" is equality of the zero padded byte strings. That is O(S) steps of O(length / 8)
// each, independent of how long the IDs are (no 2^length arithmetic).
func checkComplete(ordered ShardingScheme) error {
	if len(ordered) == 0 {
		return nil
	}
	if first := ordered[0]; !allBits(first, 0) {
		return fmt.Errorf("scheme does not cover the whole shard tree: nothing before %s", first)
	}
	for i := 1; i < len(ordered); i++ {
		end, overflow := shardIDEnd(ordered[i-1])
		if overflow || !equalPadded(end, ordered[i].bits) {
			return fmt.Errorf("scheme does not cover the whole shard tree: gap between %s and %s", ordered[i-1], ordered[i])
		}
	}
	if last := ordered[len(ordered)-1]; !allBits(last, 1) {
		return fmt.Errorf("scheme does not cover the whole shard tree: nothing after %s", last)
	}
	return nil
}

// allBits returns true if all bits of the shard ID are equal to bit (0 or 1).
func allBits(id ShardID, bit byte) bool {
	for i := uint(0); i < id.length; i++ {
		if (id.bits[i/8]>>(7-i%8))&1 != bit {
			return false
		}
	}
	return true
}

// shardIDEnd returns the bits of id+1 as a len(id)-bit integer (unused bits zero), overflow is true
// when all bits of the id are 1 (the interval of the shard ends at 1).
func shardIDEnd(id ShardID) (end []byte, overflow bool) {
	end = slices.Clone(id.bits)
	for i := int(id.length) - 1; i >= 0; i-- {
		mask := byte(1) << (7 - uint(i)%8)
		if end[i/8]&mask == 0 {
			end[i/8] |= mask
			return end, false
		}
		end[i/8] &^= mask
	}
	return nil, true
}

// equalPadded compares byte strings as if the shorter one was padded with zero bytes.
func equalPadded(a, b []byte) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	return bytes.Equal(a, b[:len(a)]) && !slices.ContainsFunc(b[len(a):], func(c byte) bool { return c != 0 })
}
