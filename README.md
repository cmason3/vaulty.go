## Vaulty
### Encrypt/Decrypt with ChaCha20-Poly1305

Vaulty is an extremely lightweight encryption/decryption tool which uses ChaCha20-Poly1305 to provide 256-bit authenticated symmetric encryption (AEAD) using Scrypt as the password based key derivation function. It also supports public key (asymmetric) encryption via ECDH (Elliptic Curve Diffie-Hellman) using X25519.

It can be used to encrypt/decrypt files, or `stdin` if you don't specify any files. If encrypting `stdin` then the output will be Base64 encoded whereas if encrypting a file then it won't and it will have a `.vlt` extension added to indicate it has been encrypted.

```
Usage: vaulty keygen <keyfile>
              encrypt [-r <public id>] [files]
              decrypt [-k <keyfile>] [files]
              chpass [files]
              sha256 [files]
```

#### Usage - Symmetric Encryption

Symmetric encryption is where encryption and decryption happens with the same password/key. If Alice is sharing an encrypted file with Bob then both [Alice and Bob](https://en.wikipedia.org/wiki/Alice_and_Bob) need to know the same password/key. With symmetric encryption both parties need a secure mechanism to exchange the password/key without anyone else (i.e. Eve) obtaining it.

```
echo "Hello World" | vaulty encrypt
  $VAULTY;AY3eJ98NF6WFDMAP62lRdl58A2db5XJ2gNvKd0nmDs5ZrmNlJ8TSURpxc3bNF1iGw77dHA==

echo "$VAULTY;..." | vaulty decrypt
  Hello World
```

#### Usage - Public Key (Asymmetric) Encryption

Public key encryption is asymmetric which means Alice no longer needs to share the same password/key with Bob. With asymmetric encryption Alice and Bob both generate a keypair which comprises of a private key and a public key. The private key (as the name suggests) must remain private and is encrypted where the password is never shared. The public key should be given to anyone who wishes to securely communicate with you. There is a lot of complicated maths involved here using Eliptic Curves with Diffie-Hellman [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) that allows two parties to agree on a shared secret without ever exchanging that secret. If Alice wants to share an encrypted file with Bob then she needs to encrypt it using Bob's public key. Bob will then use his private key to decrypt it, as only the paired private key is able to decrypt it. In the opposite direction if Bob wishes to share an encrypted file with Alice then he would encrypt it using Alice's public key.

The specific method adopted here is based on [ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) which uses an ephemeral key pair for ECDH. When Alice wants to encrypt something for Bob, she generates a new public/private key pair. She then performs ECDH with the newly generated private key and Bob's known public key, which is then expanded using HKDF to produce an encryption key that is passed to ChaCha20-Poly1305. When the ciphertext is sent to Bob, it includes the corresponding public key that was generated - Bob then performs ECDH using that public key and his private key to derive the same encryption key to decrypt the ciphertext. In this scenario Bob has no way to determine that it was indeed Alice that encrypted it (this is fixed if we allow Alice to sign the ciphertext with her actual private key and send the signature with the ciphertext so that Bob can validate with Alice's known public key).

With symmetric encryption the challenge is securely exchanging the password/key, but with asymmetric encryption the challenge is proving what you think is Bob's public key actually is Bob's public key. What if Eve was sitting between Alice and Bob and when Bob sent his public key, Eve went and swapped it with hers? When exchanging public keys you must use another method to verify you are actually in possession of Bob's public key - in simplest terms Alice needs to verify Bob's public key fingerprint with Bob himself and vice versa.

```
vaulty keygen vaulty.key
  // Public ID: pzeqacudvrxyc79qgmdw47lq3vtghjnraz59pkqm8lxf7vs0xexsr3a7nx
  $VAULTY;ARqtIXUoc7Qi2aip88u7SjrjJQMUGec1zwAAAABM37u0hj31foETHau8vgUQZbfm13ln76nQ
  uarFlWYXgtZolkJdDtTV7FLIui+eNjc=

echo "Hello World" | vaulty encrypt -r <Public ID>
  $VAULTY;8SA7mU2Uqe4c/506CZmnbfT6el81nTSLnbPOV4DEk9Lwe8jqtB8UKnScUYojlw5MHtR2R1lF
  p7hj0z80fU8Fjw2ZkESXuQUHYSEV9y4=

echo "$VAULTY;..." | vaulty decrypt -k vaulty.key
  Hello World
```

#### Usage - SHA256

```
echo "Hello World" | vaulty sha256
  d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26  -
```

