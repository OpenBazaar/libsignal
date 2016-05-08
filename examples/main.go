package main

import (
	"github.com/OpenBazaar/libsignal"
	"fmt"
)

func main() {
	// Create clients for Alice and Bob.
	alice, _ := libsignal.NewClient("./alice/", "")
	bob, _ := libsignal.NewClient("./bob/", "")

	// Build an encrypted message from Alice to Bob.
	// To start the secession we have to pass in Bob's signed prekey, one of his unsigned prekeys,
	// and his identity key. For this example we will just load them from Bob's directory. In
	// production Alice will need to fetch these keys from somewhere else. Also keep in mind, the files
	// we are loading here contain Bob's private keys, which means Bob should not share these files
	// with Alice without first removing the private keys.
	pk, _ := bob.Store.LoadRandomPreKey()
	id, _ := bob.Store.GetIdentityKeyPair()
	sk := bob.Store.LoadSignedPreKeys()[0]
	pkb, _ := libsignal.MakePreKeyBundle(pk, sk, *id)

	// Create the ciphertext.
	ciphertext1, _ := alice.BuildMessage("hello world", "bob", pkb)

	// Bob decrypts messages
	decryptedMessage1, _ := bob.HandleReceivedMessage(ciphertext1)
	fmt.Println(decryptedMessage1)
}
