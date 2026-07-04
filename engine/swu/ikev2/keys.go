package ikev2

import (
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
)

var ErrUnsupportedTransform = errors.New("unsupported ikev2 transform")

type KeyMaterialProfile struct {
	PRF                     crypto.Hash
	EncryptionID            uint16
	EncryptionKeyLength     int
	EncryptionBlockSize     int
	IntegrityID             uint16
	IntegrityKeyLength      int
	IntegrityChecksumLength int
	PRFKeyLength            int
}

func (p KeyMaterialProfile) RequiredLength() int {
	return p.PRFKeyLength + p.IntegrityKeyLength*2 + p.EncryptionKeyLength*2 + p.PRFKeyLength*2
}

type IKEKeys struct {
	Profile KeyMaterialProfile
	SKD     []byte
	SKAi    []byte
	SKAr    []byte
	SKEi    []byte
	SKEr    []byte
	SKPi    []byte
	SKPr    []byte
}

func KeyMaterialProfileFromSA(sa SecurityAssociation) (KeyMaterialProfile, error) {
	if len(sa.Proposals) == 0 {
		return KeyMaterialProfile{}, fmt.Errorf("%w: no proposals", ErrInvalidSA)
	}
	p := sa.Proposals[0]
	encr, ok := findTransform(p, TransformENCR)
	if !ok {
		return KeyMaterialProfile{}, fmt.Errorf("%w: missing ENCR", ErrUnsupportedTransform)
	}
	prf, ok := findTransform(p, TransformPRF)
	if !ok {
		return KeyMaterialProfile{}, fmt.Errorf("%w: missing PRF", ErrUnsupportedTransform)
	}
	integ, ok := findTransform(p, TransformINTEG)
	if !ok {
		return KeyMaterialProfile{}, fmt.Errorf("%w: missing INTEG", ErrUnsupportedTransform)
	}
	prfHash, err := PRFHashForTransform(prf.ID)
	if err != nil {
		return KeyMaterialProfile{}, err
	}
	encrKeyLen, blockSize, err := encryptionProfile(encr)
	if err != nil {
		return KeyMaterialProfile{}, err
	}
	integKeyLen, checksumLen, err := integrityProfile(integ.ID)
	if err != nil {
		return KeyMaterialProfile{}, err
	}
	return KeyMaterialProfile{
		PRF:                     prfHash,
		EncryptionID:            encr.ID,
		EncryptionKeyLength:     encrKeyLen,
		EncryptionBlockSize:     blockSize,
		IntegrityID:             integ.ID,
		IntegrityKeyLength:      integKeyLen,
		IntegrityChecksumLength: checksumLen,
		PRFKeyLength:            prfHash.Size(),
	}, nil
}

func SplitIKEKeys(profile KeyMaterialProfile, keyMaterial []byte) (IKEKeys, error) {
	need := profile.RequiredLength()
	if need <= 0 {
		return IKEKeys{}, fmt.Errorf("%w: invalid key profile", ErrUnsupportedTransform)
	}
	if len(keyMaterial) < need {
		return IKEKeys{}, fmt.Errorf("%w: key material %d < %d", ErrInvalidLength, len(keyMaterial), need)
	}
	rest := keyMaterial
	take := func(n int) []byte {
		out := append([]byte(nil), rest[:n]...)
		rest = rest[n:]
		return out
	}
	return IKEKeys{
		Profile: profile,
		SKD:     take(profile.PRFKeyLength),
		SKAi:    take(profile.IntegrityKeyLength),
		SKAr:    take(profile.IntegrityKeyLength),
		SKEi:    take(profile.EncryptionKeyLength),
		SKEr:    take(profile.EncryptionKeyLength),
		SKPi:    take(profile.PRFKeyLength),
		SKPr:    take(profile.PRFKeyLength),
	}, nil
}

func PRFHashForTransform(id uint16) (crypto.Hash, error) {
	switch id {
	case PRF_HMAC_SHA1:
		return crypto.SHA1, nil
	case PRF_HMAC_SHA2_256:
		return crypto.SHA256, nil
	case PRF_HMAC_SHA2_384:
		return crypto.SHA384, nil
	case PRF_HMAC_SHA2_512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("%w: PRF %d", ErrUnsupportedTransform, id)
	}
}

func findTransform(p Proposal, transformType uint8) (Transform, bool) {
	for _, tr := range p.Transforms {
		if tr.Type == transformType {
			return tr, true
		}
	}
	return Transform{}, false
}

func encryptionProfile(t Transform) (keyLen int, blockSize int, err error) {
	switch t.ID {
	case ENCR_AES_CBC:
		bits := transformKeyLength(t)
		if bits == 0 {
			bits = 128
		}
		if bits != 128 && bits != 192 && bits != 256 {
			return 0, 0, fmt.Errorf("%w: AES-CBC key length %d", ErrUnsupportedTransform, bits)
		}
		return int(bits / 8), 16, nil
	default:
		return 0, 0, fmt.Errorf("%w: ENCR %d", ErrUnsupportedTransform, t.ID)
	}
}

func integrityProfile(id uint16) (keyLen int, checksumLen int, err error) {
	switch id {
	case INTEG_HMAC_SHA1_96:
		return crypto.SHA1.Size(), 12, nil
	case INTEG_HMAC_SHA2_256_128:
		return crypto.SHA256.Size(), 16, nil
	case INTEG_HMAC_SHA2_384_192:
		return crypto.SHA384.Size(), 24, nil
	case INTEG_HMAC_SHA2_512_256:
		return crypto.SHA512.Size(), 32, nil
	default:
		return 0, 0, fmt.Errorf("%w: INTEG %d", ErrUnsupportedTransform, id)
	}
}

func transformKeyLength(t Transform) uint16 {
	for _, attr := range t.Attributes {
		if attr.Type == AttributeKeyLength && len(attr.Value) >= 2 {
			return binary.BigEndian.Uint16(attr.Value[:2])
		}
	}
	return 0
}
