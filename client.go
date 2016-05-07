package signalratchet

import (
	"github.com/janimo/textsecure/axolotl"
	"github.com/janimo/textsecure/protobuf"
	"github.com/golang/protobuf/proto"
	envelope "github.com/OpenBazaar/libsignal/protobuf"
	"fmt"
	"errors"
)

type Client struct {
	Store          *store
	IdentityKey    *axolotl.IdentityKeyPair
 	PreKeys        *preKeyState
	DeviceID       uint32
	PeerID         string
}

var identityKey *axolotl.IdentityKeyPair

type OutgoingMessage struct {
	Recipient    string
	Msg          string
	Flags        uint32
}

func NewClient(datastorePath string, password string) (*Client, error) {
	store, err := NewStore(password, datastorePath)
	textSecureStore = store
	if err != nil {
		return nil, err
	}
	if !store.valid(){
		identityKey = axolotl.GenerateIdentityKeyPair()
		err := store.SetIdentityKeyPair(identityKey)
		if err != nil {
			return nil, err
		}
		err = generatePreKeys()
		if err != nil {
			return nil, err
		}
		store.SetLocalRegistrationID(randUint32())
	}
	identityKey, err = store.GetIdentityKeyPair()
	if err != nil {
		return nil, err
	}
	k := store.LoadSignedPreKeys()[0]
	signedKey = &k
	err = generatePreKeyState()
	if err != nil {
		return nil, err
	}
	rid, err := store.GetLocalRegistrationID()
	if err != nil {
		return nil, err
	}
	c := new(Client)
	c.DeviceID = rid
	c.Store = store
	c.PreKeys = preKeys
	c.IdentityKey = identityKey
	return c, nil
}

func makePreKeyBundle(pkr *preKeyResponse) (*axolotl.PreKeyBundle, error) {

	if len(pkr.Devices) != 1 {
		return nil, fmt.Errorf("no prekeys for contact")
	}

	d := pkr.Devices[0]

	if d.PreKey == nil {
		return nil, fmt.Errorf("no prekey for contact")
	}
	decPK, err := decodeKey(d.PreKey.PublicKey)
	if err != nil {
		return nil, err
	}
	if d.SignedPreKey == nil {
		return nil, fmt.Errorf("no signed prekey for contact")
	}
	decSPK, err := decodeKey(d.SignedPreKey.PublicKey)
	if err != nil {
		return nil, err
	}
	decSig, err := decodeSignature(d.SignedPreKey.Signature)
	if err != nil {
		return nil, err
	}
	decIK, err := decodeKey(pkr.IdentityKey)
	if err != nil {
		return nil, err
	}
	pkb, err := axolotl.NewPreKeyBundle(
		d.RegistrationID, d.DeviceID, d.PreKey.ID,
		axolotl.NewECPublicKey(decPK), int32(d.SignedPreKey.ID), axolotl.NewECPublicKey(decSPK),
		decSig, axolotl.NewIdentityKey(decIK))
	if err != nil {
		return nil, err
	}

	return pkb, nil
}

func (c *Client) BuildMessage(plaintext string, recipient string, pkr *preKeyResponse) ([]byte, error) {
	msg := &OutgoingMessage{
		Recipient: recipient,
		Msg: plaintext,
		Flags: 0,
	}
	paddedMessage, err := createMessage(msg)
	if err != nil {
		return nil, err
	}
	recid := msg.Recipient

	if !c.Store.ContainsSession(recid, c.DeviceID) {
		pkb, err := makePreKeyBundle(pkr)
		if err != nil {
			return nil, err
		}
		sb := axolotl.NewSessionBuilder(c.Store, c.Store, c.Store, c.Store, recid, c.DeviceID)
		err = sb.BuildSenderSession(pkb)
		if err != nil {
			return nil, err
		}
	}
	sc := axolotl.NewSessionCipher(c.Store, c.Store, c.Store, c.Store, recid, c.DeviceID)
	encryptedMessage, messageType, err := sc.SessionEncryptMessage(paddedMessage)
	if err != nil {
		return nil, err
	}
	m := new(envelope.Envelope)
	switch messageType {
	case 1:
		m.Type = envelope.Envelope_CIPHERTEXT
	case 2:
		m.Type = envelope.Envelope_KEY_EXCHANGE
	case 3:
		m.Type = envelope.Envelope_PREKEY_BUNDLE
	case 5:
		m.Type = envelope.Envelope_RECEIPT
	}
	m.Ciphertext = encryptedMessage
	b, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func createMessage(msg *OutgoingMessage) ([]byte, error) {
	dm := &textsecure.DataMessage{}
	if msg.Msg != "" {
		dm.Body = &msg.Msg
	}

	dm.Flags = &msg.Flags

	b, err := proto.Marshal(dm)
	if err != nil {
		return nil, err
	}
	return padMessage(b), nil
}

func padMessage(msg []byte) []byte {
	l := (len(msg) + 160)
	l = l - l%160
	n := make([]byte, l)
	copy(n, msg)
	n[len(msg)] = 0x80
	return n
}

func stripPadding(msg []byte) []byte {
	for i := len(msg) - 1; i >= 0; i-- {
		if msg[i] == 0x80 {
			return msg[:i]
		}
	}
	return msg
}

var EndSessionFlag uint32 = 1

func handleFlags(src string, dm *textsecure.DataMessage) (uint32, error) {
	flags := uint32(0)
	if dm.GetFlags() == uint32(textsecure.DataMessage_END_SESSION) {
		flags = EndSessionFlag
		textSecureStore.DeleteAllSessions(src)
	}
	return flags, nil
}

// ErrInvalidMACForMessage signals an incoming message with invalid MAC.
var ErrInvalidMACForMessage = errors.New("invalid MAC for incoming message")

// MessageTypeNotImplementedError is raised in the unlikely event that an unhandled protocol message type is received.
var MessageTypeNotImplementedError = errors.New("envelope type not implemented")

// Authenticate and decrypt a received message
func (c *Client) HandleReceivedMessage(msg []byte) (string, error) {
	env := &envelope.Envelope{}
	err := proto.Unmarshal(msg, env)
	if err != nil {
		return "", err
	}
	recid := string(randUint32())
	localid, _ := c.Store.GetLocalRegistrationID()
	sc := axolotl.NewSessionCipher(c.Store, c.Store, c.Store, c.Store, recid, localid)
	switch env.Type {

	case envelope.Envelope_PREKEY_BUNDLE:
		pkwm, err := axolotl.LoadPreKeyWhisperMessage(env.Ciphertext)
		if err != nil {
			return "", err
		}
		b, err := sc.SessionDecryptPreKeyWhisperMessage(pkwm)
		if _, ok := err.(axolotl.DuplicateMessageError); ok {
			fmt.Printf("Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return "", err
		}
		if _, ok := err.(axolotl.PreKeyNotFoundError); ok {
			fmt.Printf("Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return "", err
		}
		if _, ok := err.(axolotl.InvalidMessageError); ok {
			fmt.Printf("Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return "", err
		}
		if err != nil {
			return "", err
		}
		b = stripPadding(b)
		dm := &textsecure.DataMessage{}
		err = proto.Unmarshal(b, dm)
		if err != nil {
			return "", err
		}
		return *dm.Body, nil

	default:
		return "", MessageTypeNotImplementedError
	}
}