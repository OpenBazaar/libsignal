package libsignal

import (
	"github.com/OpenBazaar/libsignal/ratchet"
	"github.com/golang/protobuf/proto"
	"github.com/OpenBazaar/libsignal/protobuf"
	"fmt"
	"errors"
	"strconv"
)

type Client struct {
	Store          *store
	IdentityKey    *ratchet.IdentityKeyPair
 	PreKeys        *preKeyState
	DeviceID       uint32
	PeerID         string
}

var identityKey *ratchet.IdentityKeyPair

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
		identityKey = ratchet.GenerateIdentityKeyPair()
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

func MakePreKeyBundle(preKey ratchet.PreKeyRecord, signedPreKey ratchet.SignedPreKeyRecord, identityKey ratchet.IdentityKeyPair) (*ratchet.PreKeyBundle, error) {
	pkb, err := ratchet.NewPreKeyBundle(
		0, randUint32(), *preKey.Pkrs.Id,
		ratchet.NewECPublicKey(preKey.Pkrs.PublicKey),
		int32(*signedPreKey.Spkrs.Id), ratchet.NewECPublicKey(signedPreKey.Spkrs.PublicKey),
		signedPreKey.Spkrs.Signature, ratchet.NewIdentityKey(identityKey.PublicKey.Serialize()[1:]))
	if err != nil {
		return nil, err
	}

	return pkb, nil
}

func (c *Client) BuildMessage(plaintext string, recipient string, pkb *ratchet.PreKeyBundle) ([]byte, error) {
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
		sb := ratchet.NewSessionBuilder(c.Store, c.Store, c.Store, c.Store, recid, c.DeviceID)
		err = sb.BuildSenderSession(pkb)
		if err != nil {
			return nil, err
		}
	}
	sc := ratchet.NewSessionCipher(c.Store, c.Store, c.Store, c.Store, recid, c.DeviceID)
	encryptedMessage, messageType, err := sc.SessionEncryptMessage(paddedMessage)
	if err != nil {
		return nil, err
	}
	m := new(libsignal.Envelope)
	switch messageType {
	case 1:
		m.Type = libsignal.Envelope_CIPHERTEXT
	case 2:
		m.Type = libsignal.Envelope_KEY_EXCHANGE
	case 3:
		m.Type = libsignal.Envelope_PREKEY_BUNDLE
	case 5:
		m.Type = libsignal.Envelope_RECEIPT
	}
	m.DataMessage = encryptedMessage
	b, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func createMessage(msg *OutgoingMessage) ([]byte, error) {
	dm := &libsignal.DataMessage{}
	if msg.Msg != "" {
		dm.Body = msg.Msg
	}

	dm.Flags = msg.Flags

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

func handleFlags(src string, dm *libsignal.DataMessage) (uint32, error) {
	flags := uint32(0)
	if dm.Flags == uint32(libsignal.DataMessage_END_SESSION) {
		flags = EndSessionFlag
		textSecureStore.DeleteAllSessions(src)
	}
	return flags, nil
}

// ErrInvalidMACForMessage signals an incoming message with invalid MAC.
var ErrInvalidMACForMessage = errors.New("invalid MAC for incoming message")

// ErrInvalidMACForMessage signals an incoming message with invalid MAC.
var ErrCouldNotDecrypt = errors.New("could not decrypt message using any open sessions")

// MessageTypeNotImplementedError is raised in the unlikely event that an unhandled protocol message type is received.
var MessageTypeNotImplementedError = errors.New("envelope type not implemented")

// Authenticate and decrypt a received message
func (c *Client) HandleReceivedMessage(msg []byte) (string, error) {
	env := &libsignal.Envelope{}
	err := proto.Unmarshal(msg, env)
	if err != nil {
		return "", err
	}
	fmt.Printf("Handle Message %s\n", env)
	switch env.Type {
	case libsignal.Envelope_CIPHERTEXT:
		for _, session := range(c.Store.GetSessionRecipients()){
			localid, _ := c.Store.GetLocalRegistrationID()
			sc := ratchet.NewSessionCipher(c.Store, c.Store, c.Store, c.Store, session, localid)
			wm, err := ratchet.LoadWhisperMessage(env.DataMessage)
			if err != nil {
				return "", err
			}
			b, err := sc.SessionDecryptWhisperMessage(wm)
			if err == nil {
				b = stripPadding(b)
				dm := &libsignal.DataMessage{}
				err = proto.Unmarshal(b, dm)
				if err != nil {
					return "", err
				}
				return dm.Body, nil
			}
		}
		return "", ErrCouldNotDecrypt

	case libsignal.Envelope_PREKEY_BUNDLE:
		recid := strconv.Itoa(int(randUint32()))
		localid, _ := c.Store.GetLocalRegistrationID()
		sc := ratchet.NewSessionCipher(c.Store, c.Store, c.Store, c.Store, recid, localid)
		pkwm, err := ratchet.LoadPreKeyWhisperMessage(env.DataMessage)
		if err != nil {
			return "", err
		}
		b, err := sc.SessionDecryptPreKeyWhisperMessage(pkwm)
		if _, ok := err.(ratchet.DuplicateMessageError); ok {
			fmt.Printf("Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return "", err
		}
		if _, ok := err.(ratchet.PreKeyNotFoundError); ok {
			fmt.Printf("Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return "", err
		}
		if _, ok := err.(ratchet.InvalidMessageError); ok {
			fmt.Printf("Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return "", err
		}
		if err != nil {
			return "", err
		}
		b = stripPadding(b)
		dm := &libsignal.DataMessage{}
		err = proto.Unmarshal(b, dm)
		if err != nil {
			return "", err
		}
		return dm.Body, nil

	default:
		return "", MessageTypeNotImplementedError
	}
}