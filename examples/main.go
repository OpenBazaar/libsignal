package main

import (
	"github.com/OpenBazaar/libsignal"
	"fmt"
)

func main() {
	// Create clients for Alice and Bob.
	alice, _ := signalratchet.NewClient("./alice/", "")
	bob, _ := signalratchet.NewClient("./bob/", "")

	// Build encrypted message from Alice to Bob
	sk, _ := bob.Store.LoadSignedPreKey(2099347)
	pk, _ := bob.Store.LoadPreKey(335143)
	id, _ := bob.Store.GetIdentityKeyPair()
	idser := id.PublicKey.Serialize()
	r := signalratchet.MakePrekeyResponse(idser, sk, pk)
	m, _ := alice.BuildMessage("hello world", "bob", &r)

	decryptedMessage, _ := bob.HandleReceivedMessage(m)
	fmt.Println(decryptedMessage)

}
