package ikev2

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var ErrInvalidSKPayload = errors.New("invalid ikev2 sk payload")

func ProtectMessage(header Header, keys IKEKeys, fromInitiator bool, inner []Payload, iv []byte) (Message, []byte, error) {
	if len(inner) == 0 {
		return Message{}, nil, fmt.Errorf("%w: no inner payloads", ErrInvalidSKPayload)
	}
	if err := validateKeySet(keys); err != nil {
		return Message{}, nil, err
	}
	firstInner, innerBytes, err := MarshalPayloads(inner)
	if err != nil {
		return Message{}, nil, err
	}
	blockSize := keys.Profile.EncryptionBlockSize
	if len(iv) == 0 {
		iv, err = randomBytes(rand.Reader, blockSize)
		if err != nil {
			return Message{}, nil, err
		}
	}
	if len(iv) != blockSize {
		return Message{}, nil, fmt.Errorf("%w: IV length %d != %d", ErrInvalidSKPayload, len(iv), blockSize)
	}
	plain := padIKEPlaintext(innerBytes, blockSize)
	encrKey, integKey := keysForDirection(keys, fromInitiator)
	ciphertext, err := encryptAESCBC(encrKey, iv, plain)
	if err != nil {
		return Message{}, nil, err
	}
	bodyNoICV := make([]byte, 0, len(iv)+len(ciphertext))
	bodyNoICV = append(bodyNoICV, iv...)
	bodyNoICV = append(bodyNoICV, ciphertext...)
	icvLen := keys.Profile.IntegrityChecksumLength
	body := append(append([]byte(nil), bodyNoICV...), make([]byte, icvLen)...)
	msg := Message{
		Header: header,
		Payloads: []Payload{{
			Type:        PayloadSK,
			NextPayload: firstInner,
			Body:        body,
		}},
	}
	rawWithZeros, err := msg.MarshalBinary()
	if err != nil {
		return Message{}, nil, err
	}
	checksum, err := IntegrityChecksum(keys.Profile, integKey, rawWithZeros[:len(rawWithZeros)-icvLen])
	if err != nil {
		return Message{}, nil, err
	}
	copy(msg.Payloads[0].Body[len(bodyNoICV):], checksum)
	raw := append([]byte(nil), rawWithZeros...)
	copy(raw[len(raw)-icvLen:], checksum)
	return msg, raw, nil
}

func UnprotectMessage(raw []byte, keys IKEKeys, fromInitiator bool) (Message, []Payload, error) {
	if err := validateKeySet(keys); err != nil {
		return Message{}, nil, err
	}
	msg, err := ParseMessage(raw)
	if err != nil {
		return Message{}, nil, err
	}
	if len(msg.Payloads) != 1 || msg.Payloads[0].Type != PayloadSK {
		return Message{}, nil, fmt.Errorf("%w: expected single SK payload", ErrInvalidSKPayload)
	}
	sk := msg.Payloads[0]
	blockSize := keys.Profile.EncryptionBlockSize
	icvLen := keys.Profile.IntegrityChecksumLength
	if len(sk.Body) < blockSize+icvLen || len(raw) < icvLen {
		return Message{}, nil, fmt.Errorf("%w: body too short", ErrInvalidSKPayload)
	}
	bodyNoICV := sk.Body[:len(sk.Body)-icvLen]
	gotICV := sk.Body[len(sk.Body)-icvLen:]
	encrKey, integKey := keysForDirection(keys, fromInitiator)
	expected, err := IntegrityChecksum(keys.Profile, integKey, raw[:len(raw)-icvLen])
	if err != nil {
		return Message{}, nil, err
	}
	if !hmac.Equal(gotICV, expected) {
		return Message{}, nil, fmt.Errorf("%w: integrity check failed", ErrInvalidSKPayload)
	}
	iv := bodyNoICV[:blockSize]
	ciphertext := bodyNoICV[blockSize:]
	plain, err := decryptAESCBC(encrKey, iv, ciphertext)
	if err != nil {
		return Message{}, nil, err
	}
	innerBytes, err := unpadIKEPlaintext(plain)
	if err != nil {
		return Message{}, nil, err
	}
	inner, err := ParsePayloads(sk.NextPayload, innerBytes)
	if err != nil {
		return Message{}, nil, err
	}
	return msg, inner, nil
}

func IntegrityChecksum(profile KeyMaterialProfile, key, data []byte) ([]byte, error) {
	hash, err := integrityHash(profile.IntegrityID)
	if err != nil {
		return nil, err
	}
	if !hash.Available() {
		return nil, fmt.Errorf("%w: integrity hash %v", ErrUnsupportedPRF, hash)
	}
	mac := hmac.New(hash.New, key)
	_, _ = mac.Write(data)
	sum := mac.Sum(nil)
	if profile.IntegrityChecksumLength <= 0 || profile.IntegrityChecksumLength > len(sum) {
		return nil, fmt.Errorf("%w: checksum length %d", ErrInvalidSKPayload, profile.IntegrityChecksumLength)
	}
	return append([]byte(nil), sum[:profile.IntegrityChecksumLength]...), nil
}

func RandomIV(random io.Reader, profile KeyMaterialProfile) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	return randomBytes(random, profile.EncryptionBlockSize)
}

func validateKeySet(keys IKEKeys) error {
	p := keys.Profile
	if p.EncryptionID != ENCR_AES_CBC {
		return fmt.Errorf("%w: ENCR %d", ErrUnsupportedTransform, p.EncryptionID)
	}
	if p.EncryptionBlockSize <= 0 || p.EncryptionKeyLength <= 0 || p.IntegrityKeyLength <= 0 || p.IntegrityChecksumLength <= 0 {
		return fmt.Errorf("%w: incomplete key profile", ErrInvalidSKPayload)
	}
	if len(keys.SKEi) != p.EncryptionKeyLength || len(keys.SKEr) != p.EncryptionKeyLength ||
		len(keys.SKAi) != p.IntegrityKeyLength || len(keys.SKAr) != p.IntegrityKeyLength {
		return fmt.Errorf("%w: key length mismatch", ErrInvalidSKPayload)
	}
	return nil
}

func keysForDirection(keys IKEKeys, fromInitiator bool) (encrKey, integKey []byte) {
	if fromInitiator {
		return keys.SKEi, keys.SKAi
	}
	return keys.SKEr, keys.SKAr
}

func padIKEPlaintext(data []byte, blockSize int) []byte {
	padLen := (blockSize - ((len(data) + 1) % blockSize)) % blockSize
	out := make([]byte, 0, len(data)+padLen+1)
	out = append(out, data...)
	for i := 0; i < padLen; i++ {
		out = append(out, byte(i+1))
	}
	out = append(out, byte(padLen))
	return out
}

func unpadIKEPlaintext(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty plaintext", ErrInvalidSKPayload)
	}
	padLen := int(data[len(data)-1])
	if padLen+1 > len(data) {
		return nil, fmt.Errorf("%w: padding length %d", ErrInvalidSKPayload, padLen)
	}
	return append([]byte(nil), data[:len(data)-padLen-1]...), nil
}

func encryptAESCBC(key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(plain)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid CBC input", ErrInvalidSKPayload)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

func decryptAESCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid CBC input", ErrInvalidSKPayload)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

func integrityHash(id uint16) (crypto.Hash, error) {
	switch id {
	case INTEG_HMAC_SHA1_96:
		return crypto.SHA1, nil
	case INTEG_HMAC_SHA2_256_128:
		return crypto.SHA256, nil
	case INTEG_HMAC_SHA2_384_192:
		return crypto.SHA384, nil
	case INTEG_HMAC_SHA2_512_256:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("%w: INTEG %d", ErrUnsupportedTransform, id)
	}
}
