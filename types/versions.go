package types

import (
	"errors"
	"fmt"
)

type CborTag = uint64
type Version = uint32

// Versioned interface is used by the structs that require versioning.
// By our convention, the version is the first field of the struct with type Version.
// Version must be greater than 0.
type Versioned interface {
	GetVersion() Version
}

const (
	// https://github.com/unicitynetwork/unicity-ids/blob/main/cbor-tags.json
	UnicityTrustBaseTag           CborTag = 39000
	UnicityCertificateTag         CborTag = 39001
	InputRecordTag                CborTag = 39002
	ShardTreeCertificateTag       CborTag = 39003
	UnicityTreeCertificateTag     CborTag = 39004
	UnicitySealTag                CborTag = 39005
	RootPartitionBlockDataTag     CborTag = 39006
	RootPartitionRoundInfoTag     CborTag = 39007
	PartitionDescriptionRecordTag CborTag = 39008
	BlockTag                      CborTag = 39009
	TransactionRecordTag          CborTag = 39010
	TransactionOrderTag           CborTag = 39011
	TxProofTag                    CborTag = 39012
	UnitStateProofTag             CborTag = 39013
)

func ErrInvalidVersion(s Versioned) error {
	// since s.GetVersion() might return a default value instead of an actual one, no need to print it
	return fmt.Errorf("invalid version (type %T)", s)
}

func EnsureVersion(data Versioned, actual, expected Version) error {
	if data.GetVersion() != expected {
		return fmt.Errorf("invalid version (type %T), expected %d, got %d", data, expected, actual)
	}
	return nil
}

func parseTaggedCBOR(b []byte, objID CborTag) (Version, []any, error) {
	tag, arr, err := Cbor.UnmarshalTagged(b)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to unmarshal as tagged CBOR: %w", err)
	}
	if tag != objID {
		return 0, nil, fmt.Errorf("expected tag %d, got %d", objID, tag)
	}
	if len(arr) == 0 {
		return 0, nil, errors.New("empty data slice")
	}
	if version, ok := arr[0].(uint64); ok {
		if version > uint64(^Version(0)) {
			return 0, nil, fmt.Errorf("version %d exceeds maximum value %d", version, ^Version(0))
		}
		return Version(version), arr, nil
	}
	return 0, nil, fmt.Errorf("expected version number to be uint64, got: %#v", arr[0])
}
