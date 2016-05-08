package libsignal

import (
	"os"
	"path/filepath"
	"time"
	"github.com/janimo/textsecure/curve25519sign"
	"github.com/OpenBazaar/libsignal/ratchet"
)

type preKeyResponseItem struct {
	DeviceID       uint32              `json:"deviceId"`
	RegistrationID uint32              `json:"registrationId"`
	SignedPreKey   *signedPreKeyEntity `json:"signedPreKey"`
	PreKey         *preKeyEntity       `json:"preKey"`
}

type preKeyResponse struct {
	IdentityKey string               `json:"identityKey"`
	Devices     []preKeyResponseItem `json:"devices"`
}

type preKeyEntity struct {
	ID        uint32 `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

type signedPreKeyEntity struct {
	ID        uint32 `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

type preKeyState struct {
	IdentityKey   string              `json:"identityKey"`
	PreKeys       []*preKeyEntity     `json:"preKeys"`
	LastResortKey *preKeyEntity       `json:"lastResortKey"`
	SignedPreKey  *signedPreKeyEntity `json:"signedPreKey"`
}

var preKeys *preKeyState

func randID() uint32 {
	return randUint32() & 0xffffff
}

func generatepreKeyEntity(record *ratchet.PreKeyRecord) *preKeyEntity {
	entity := &preKeyEntity{}
	entity.ID = *record.Pkrs.Id
	entity.PublicKey = encodeKey(record.Pkrs.PublicKey)
	return entity
}

func generateSignedPreKeyEntity(record *ratchet.SignedPreKeyRecord) *signedPreKeyEntity {
	entity := &signedPreKeyEntity{}
	entity.ID = *record.Spkrs.Id
	entity.PublicKey = encodeKey(record.Spkrs.PublicKey)
	entity.Signature = base64EncWithoutPadding(record.Spkrs.Signature)
	return entity
}

var preKeyRecords []*ratchet.PreKeyRecord

func generatePreKey(id uint32) error {
	kp := ratchet.NewECKeyPair()
	record := ratchet.NewPreKeyRecord(id, kp)
	err := textSecureStore.StorePreKey(id, record)
	return err
}

var signedKey *ratchet.SignedPreKeyRecord

var lastResortPreKeyID uint32 = 0xFFFFFF

var preKeyBatchSize = 100

func getNextPreKeyID() uint32 {
	return randID()
}

func generatePreKeys() error {
	if err := os.MkdirAll(textSecureStore.preKeysDir, 0700); err != nil {
		return err
	}

	startID := getNextPreKeyID()
	for i := 0; i < preKeyBatchSize; i++ {
		err := generatePreKey(startID + uint32(i))
		if err != nil {
			return err
		}
	}
	err := generatePreKey(lastResortPreKeyID)
	if err != nil {
		return err
	}
	signedKey = generateSignedPreKey()
	return nil
}

func getNextSignedPreKeyID() uint32 {
	return randID()
}

func generateSignedPreKey() *ratchet.SignedPreKeyRecord {
	kp := ratchet.NewECKeyPair()
	id := getNextSignedPreKeyID()
	var random [64]byte
	randBytes(random[:])
	priv := identityKey.PrivateKey.Key()
	signature := curve25519sign.Sign(priv, kp.PublicKey.Serialize(), random)
	record := ratchet.NewSignedPreKeyRecord(id, uint64(time.Now().UnixNano()*1000), kp, signature[:])
	textSecureStore.StoreSignedPreKey(id, record)
	return record
}

func generatePreKeyState() error {
	err := loadPreKeys()
	if err != nil {
		return err
	}
	preKeys = &preKeyState{}
	npkr := len(preKeyRecords)
	preKeys.PreKeys = make([]*preKeyEntity, npkr-1)
	for i := range preKeys.PreKeys {
		preKeys.PreKeys[i] = generatepreKeyEntity(preKeyRecords[i])
	}
	preKeys.LastResortKey = generatepreKeyEntity(preKeyRecords[npkr-1])
	preKeys.IdentityKey = base64EncWithoutPadding(identityKey.PublicKey.Serialize())
	preKeys.SignedPreKey = generateSignedPreKeyEntity(signedKey)
	return nil
}

func loadPreKeys() error {
	preKeyRecords = []*ratchet.PreKeyRecord{}
	count := 0
	err := filepath.Walk(textSecureStore.preKeysDir, func(path string, fi os.FileInfo, err error) error {
		if !fi.IsDir() {
			preKeyRecords = append(preKeyRecords, &ratchet.PreKeyRecord{})
			_, fname := filepath.Split(path)
			id, err := filenameToID(fname)
			if err != nil {
				return err
			}
			preKeyRecords[count], _ = textSecureStore.LoadPreKey(uint32(id))
			count++
		}
		return nil

	})
	return err
}