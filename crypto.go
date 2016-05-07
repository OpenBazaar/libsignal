package signalratchet

import (
	"bytes"
	"encoding/base64"
	"strings"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// randBytes returns a sequence of random bytes from the CSPRNG
func randBytes(data []byte) {
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
}

// randUint32 returns a random 32bit uint from the CSPRNG
func randUint32() uint32 {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint32(b)
}

// appendMAC returns the given message with a HMAC-SHA256 MAC appended
func appendMAC(key, b []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return m.Sum(b)
}

// verifyMAC verifies a HMAC-SHA256 MAC on a message
func verifyMAC(key, b, mac []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return hmac.Equal(m.Sum(nil), mac)
}

// telToToken calculates a truncated SHA1 hash of a phone number, to be used for contact discovery
func telToToken(tel string) string {
	s := sha1.Sum([]byte(tel))
	return base64EncWithoutPadding(s[:10])
}

// aesEncrypt encrypts the given plaintext under the given key in AES-CBC mode
func aesEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	plaintext = append(plaintext, bytes.Repeat([]byte{byte(pad)}, pad)...)

	ciphertext := make([]byte, len(plaintext))
	iv := make([]byte, 16)
	randBytes(iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return append(iv, ciphertext...), nil
}

// aesDecrypt decrypts the given ciphertext under the given key in AES-CBC mode
func aesDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext not multiple of AES blocksize")
	}

	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	pad := ciphertext[len(ciphertext)-1]
	if pad > aes.BlockSize {
		return nil, fmt.Errorf("pad value (%d) larger than AES blocksize (%d)", pad, aes.BlockSize)
	}
	return ciphertext[aes.BlockSize : len(ciphertext)-int(pad)], nil
}

// Base64-encodes without padding the result
func base64EncWithoutPadding(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	return strings.TrimRight(s, "=")
}

func encodeKey(key []byte) string {
	return base64EncWithoutPadding(append([]byte{5}, key[:]...))
}

var ErrBadPublicKey = errors.New("public key not formatted correctly")

func decodeKey(s string) ([]byte, error) {
	b, err := base64DecodeNonPadded(s)
	if err != nil {
		return nil, err
	}
	if len(b) == 33 {
		return b[1:], nil
	}
	return b, nil
}

func decodeSignature(s string) ([]byte, error) {
	b, err := base64DecodeNonPadded(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 64 {
		return nil, fmt.Errorf("signature is %d, not 64 bytes", len(b))
	}
	return b, nil
}

func base64DecodeNonPadded(s string) ([]byte, error) {
	if len(s)%4 != 0 {
		s = s + strings.Repeat("=", 4-len(s)%4)
	}
	return base64.StdEncoding.DecodeString(s)
}