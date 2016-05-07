# libsignal [WIP]
This go library is an implementation of the signal asynchronous messaging [protocol](https://whispersystems.org/blog/advanced-ratcheting/) modified for use in OpenBazaar.

Modifications include:
  - Removed all communication with the signal servers. This library only handles session state management, encryption, and decryption. It's up to you to implement a transport for the ciphertext. 
  - Removed prekey transport. Again, you need to implement a method of getting Alice's prekey bundle to Bob so that Bob can send the first message.
  - Removed message metadata. Messages are not tagged with the recipient ID. This allows them to be stored on untrusted servers without leaking metadata. The cost, however, is that to decrypt a message one must iterative over all open sessions to decrypt the message. Assuming the number of sessions a user keeps open at any given time is relatively small, this shouldn't have scaling issues. It may be possible to improve the efficiency here by tagging each message with a shared secret that ratchets forward, but at the cost of more complexity. 
  - [TODO] Identity keys switched to RSA (which is what OpenBazaar/IPFS uses). 
