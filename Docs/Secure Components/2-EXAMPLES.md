# Secure Components - Examples

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** March 22, 2022</br>
**Status:** DRAFT

---

This section includes a set of high-level examples of API usage in Swift involving `Envelope`, including example CBOR and UR output. These examples are actual, running unit tests in the [BCSwiftFoundation package](https://github.com/blockchaincommons/BCSwiftFoundation).

### Common structures used by the examples

The unit tests define a common plaintext, and three separate `Identity` objects for *Alice*, *Bob*, and *Carol*, each with a corresponding `Peer`.

```swift
  static let plaintext = "Some mysteries aren't meant to be solved.".utf8Data

  static let aliceSeed = Seed(data: ‡"82f32c855d3d542256180810797e0073")!
  static let aliceIdentity = Identity(aliceSeed, salt: "Salt")
  static let alicePeer = Peer(identity: aliceIdentity)

  static let bobSeed = Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!
  static let bobIdentity = Identity(bobSeed, salt: "Salt")
  static let bobPeer = Peer(identity: bobIdentity)

  static let carolSeed = Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!
  static let carolIdentity = Identity(carolSeed, salt: "Salt")
  static let carolPeer = Peer(identity: carolIdentity)
```

An `Identity` is derived from a source of key material such as a `Seed`, an `HDKey`, or a `Password` that produces key material using the Scrypt algorithm, and also includes a random `Salt`.

An `Identity` is kept secret, and can produce both private and public keys for signing and encryption. A `Peer` is just the public keys and `Salt` extracted from an `Identity` and can be made public. Signing and public key encryption is performed using the `Identity` of one party and the `Peer` from another.

**Note:** Due to the use of randomness in the cryptographic constructions, separate runs of the code are extremly unlikely to replicate the exact CBOR and URs below.

### Example 1: Plaintext

In this example no signing or encryption is performed.

```swift
// Alice sends a plaintext message to Bob.
let envelope = Envelope(plaintext: Self.plaintext)
let ur = envelope.ur

// ➡️ ☁️ ➡️

// Bob receives the envelope.
let receivedEnvelope = try Envelope(ur: ur)
// Bob reads the message.
XCTAssertEqual(receivedEnvelope.plaintext, Self.plaintext)
```

#### Schematic

> "An envelope containing plaintext."

```
Envelope {
    Plaintext
}
```

#### CBOR Diagnostic Notation

```
49(                 # Envelope
   [
      1,            # type 1: plaintext
      h'536f6d65206d7973746572696573206172656e2774206d65616e7420746f20626520736f6c7665642e', # payload
      []            # signatures
   ]
)
```

#### Annotated CBOR

```
d8 31                                    # tag(49): Envelope
   83                                    # array(3)
      01                                 # unsigned(1): type 1: plaintext
      5829                               # bytes(41): payload
         536f6d65206d7973746572696573206172656e2774206d65616e7420746f20626520736f6c7665642e # "Some mysteries aren't meant to be solved."
      80                                 # array(0): signatures
```

### UR

```
ur:crypto-envelope/lsadhddtgujljnihcxjnkkjkjyihjpinihjkcxhsjpihjtdijycxjnihhsjtjycxjyjlcxidihcxjkjljzkoihiedmladnvsrysa
```

### Example 2: Signed Plaintext

```swift
// Alice sends a signed plaintext message to Bob.
let envelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)
let ur = envelope.ur

// ➡️ ☁️ ➡️

// Bob receives the envelope.
let receivedEnvelope = try Envelope(ur: ur)
// Bob receives the message and verifies that it was signed by Alice.
XCTAssertTrue(receivedEnvelope.hasValidSignature(from: Self.alicePeer))
// Confirm that it wasn't signed by Carol.
XCTAssertFalse(receivedEnvelope.hasValidSignature(from: Self.carolPeer))
// Confirm that it was signed by Alice OR Carol.
XCTAssertTrue(receivedEnvelope.hasValidSignatures(from: [Self.alicePeer, Self.carolPeer], threshold: 1))
// Confirm that it was not signed by Alice AND Carol.
XCTAssertFalse(receivedEnvelope.hasValidSignatures(from: [Self.alicePeer, Self.carolPeer], threshold: 2))

// Bob reads the message.
XCTAssertEqual(receivedEnvelope.plaintext, Self.plaintext)
```

#### Schematic

> "An envelope containing signed plaintext."

```
Envelope {
    Plaintext
    Signature
}
```

#### CBOR Diagnostic Notation

```
49(                 # Envelope
   [
      1,            # type 1: Plaintext
      h'536f6d65206d7973746572696573206172656e2774206d65616e7420746f20626520736f6c7665642e',
      [             # signatures
         707(       # Signature
            [
               1,   # type 1: Schnorr
               h'1c97a6fbe5450f45da51594ce71ecb81338d2286e41af13563faa393f0d5875c52a31e1c29763c559fb398f51ae1761c12c2f08842a2a7dfffc18cb660194649',
               h''  # tag
            ]
         )
      ]
   ]
)
```

#### Annotated CBOR

```
d8 31                                    # tag(49):         Envelope
   83                                    # array(3)
      01                                 # unsigned(1):     type 1: Plaintext
      5829                               # bytes(41):       payload
         536f6d65206d7973746572696573206172656e2774206d65616e7420746f20626520736f6c7665642e # "Some mysteries aren't meant to be solved."
      81                                 # array(1):        signatures
         d9 02c3                         # tag(707):        Signature
            83                           # array(3)
               01                        # unsigned(1):     type 1: Schnorr
               5840                      # bytes(64)
                  1c97a6fbe5450f45da51594ce71ecb81338d2286e41af13563faa393f0d5875c52a31e1c29763c559fb398f51ae1761c12c2f08842a2a7dfffc18cb660194649
               40                        # bytes(0):        tag
```

### UR

```
ur:crypto-envelope/lsadhddtgujljnihcxjnkkjkjyihjpinihjkcxhsjpihjtdijycxjnihhsjtjycxjyjlcxidihcxjkjljzkoihiedmlytaaosrlsadhdfzcemsolzovwfebsfetngyhkgsvdcksblyeolgcplnvecywneciazsotmuwttllthhgmotckcedtkofngoneqdmkykcyvykocebgsawtlofwoeosurzmselkrphncffggafzskwmvtox
```

### Example 3: Multisigned Plaintext

```swift
// Alice and Carol jointly send a signed plaintext message to Bob.
let envelope = Envelope(plaintext: Self.plaintext, signers: [Self.aliceIdentity, Self.carolIdentity])
let ur = envelope.ur

// ➡️ ☁️ ➡️

// Bob receives the envelope.
let receivedEnvelope = try Envelope(ur: ur)

// Bob verifies the message was signed by both Alice and Carol.
XCTAssertTrue(receivedEnvelope.hasValidSignatures(from: [Self.alicePeer, Self.carolPeer]))

// Bob reads the message.
XCTAssertEqual(receivedEnvelope.plaintext, Self.plaintext)
```

#### Schematic

> "An envelope containing plaintext signed by several parties."

```
Envelope {
    Plaintext
    [Signature, Signature]
}
```

#### CBOR Diagnostic Notation

```
49(                     # Envelope
   [
      1,                # type 1: Plaintext
      h'536f6d65206d7973746572696573206172656e2774206d65616e7420746f20626520736f6c7665642e',
      [                 # signatures
         707(           # Signature
            [
               1,       # type 1: Schnorr
               h'4bd7af240bd6206d92c365ce610436d04f7e86b4385471fd7e671d476b0a4a46c2d95d48adc49f2cb380f0245d3b0c5a12e2d483216f8c806e8e05e1af85e92b',
               h''      # tag
            ]
         ),
         707(           # Signature
            [
               1,       # type 1: Schnorr
               h'af67970cc974a32f012919abe17e7f53de91f009ac799fda55b9012f79dd6cf29df0de42be476aed7cfbbe540271cdbedd526e1cf722db7a30c4ad1ec46376ba',
               h''      # tag
            ]
         )
      ]
   ]
)
```

#### Annotated CBOR

```
d8 31                                    # tag(49):         Envelope
   83                                    # array(3)
      01                                 # unsigned(1):     type 1: Plaintext
      5829                               # bytes(41):       payload
         536f6d65206d7973746572696573206172656e2774206d65616e7420746f20626520736f6c7665642e # "Some mysteries aren't meant to be solved."
      82                                 # array(2):        signatures
         d9 02c3                         # tag(707):        Signature
            83                           # array(3)
               01                        # unsigned(1):     type 1: Schnorr
               5840                      # bytes(64)
                  4bd7af240bd6206d92c365ce610436d04f7e86b4385471fd7e671d476b0a4a46c2d95d48adc49f2cb380f0245d3b0c5a12e2d483216f8c806e8e05e1af85e92b
               40                        # bytes(0):        tag

         d9 02c3                         # tag(707):        Signature
            83                           # array(3)
               01                        # unsigned(1):     type 1: Schnorr
               5840                      # bytes(64)
                  af67970cc974a32f012919abe17e7f53de91f009ac799fda55b9012f79dd6cf29df0de42be476aed7cfbbe540271cdbedd526e1cf722db7a30c4ad1ec46376ba
               40                        # bytes(0):        tag
```

#### UR

```
ur:crypto-envelope/lsadhddtgujljnihcxjnkkjkjyihjpinihjkcxhsjpihjtdijycxjnihhsjtjycxjyjlcxidihcxjkjljzkoihiedmlftaaosrlsadhdfzgrtspedkbdtbcxjnmosrihtohsaaentigwkblnqzetghjszckbiocafljebkgefgsatahlfdpmssnedwqdlawtdkhlfrbnhtbgvotylscljllklajtmnahvypelpwldnfztaaosrlsadhdfzpeiomsbnsojyotdladdtcfpyvykblbguuemewtaspskknetngorhaddlkkutjzwzntwtuefwrnflimwekezornghaojssnrnutgmjtceylcpuykndysspmckssiakordfzontotazm
```

### Example 4: Symmetric Encryption

```swift
// Alice and Bob have agreed to use this key.
let key = SymmetricKey()

// Alice sends a message encrypted with the key to Bob.
let envelope = Envelope(plaintext: Self.plaintext, key: key)
let ur = envelope.ur

// ➡️ ☁️ ➡️

// Bob receives the envelope.
let receivedEnvelope = try Envelope(ur: ur)

// Bob decrypts and reads the message.
XCTAssertEqual(receivedEnvelope.plaintext(with: key), Self.plaintext)

// Can't read with no key.
XCTAssertNil(receivedEnvelope.plaintext)

// Can't read with incorrect key.
XCTAssertNil(receivedEnvelope.plaintext(with: SymmetricKey()))
```

#### Schematic

> "An envelope containing a encrypted message."

```
Envelope {
    Message {           |
        Plaintext       | ENCRYPTED
    }                   |
    Permit: symmetric
}
```

#### CBOR Diagnostic Notation

```
49(                                                 # Envelope
   [
      2,                                            # type 2: encrypted
      48(                                           # Message
         [
            1,                                      # type 1: IETF-ChaCha20-Poly1305
            h'ec9faf81af0c7c6e27f6625a1286f7d5be106b806d60f7148d7746a5a8047012797217dbec56d8a577', # ciphertext
            h'',                                    # aad
            h'f5c5440156a817178da89c9a',            # nonce
            h'b8cff57f722dfa88dbde8e55e0647bac'     # auth
         ]
      ),
      702(                                          # Permit
         [1]                                        # type 1: symmetric
      )
   ]
)
```

#### Annotated CBOR

```
d8 31                                    # tag(49):         Envelope
   83                                    # array(3)
      02                                 # unsigned(2):     type 2: encrypted
      d8 30                              # tag(48):         Message
         85                              # array(5)
            01                           # unsigned(1):     type 1: IETF-ChaCha20-Poly1305
            5829                         # bytes(41):       ciphertext
               ec9faf81af0c7c6e27f6625a1286f7d5be106b806d60f7148d7746a5a8047012797217dbec56d8a577
            40                           # bytes(0):        aad
            4c                           # bytes(12):       nonce
               f5c5440156a817178da89c9a
            50                           # bytes(16):       auth
               b8cff57f722dfa88dbde8e55e0647bac
      d9 02be                            # tag(702):        Permit
         81                              # array(1)
            01                           # unsigned(1):     type 1: symmetric
```

#### UR

```
ur:crypto-envelope/lsaotpdylpadhddtwpnepelypebnkejtdiynidhtbglnyltlrnbejelajnhnylbblgktfgonpdaajobgkkjpchuywphftponktfzgsykskfyadhfpdchchlgpdnsnygdrotkyklbjpdpzslouyuemngovtiekgpstaaornlyadndmdpsfx
```

### Example 5: Sign-Then-Encrypt

```swift
// Alice and Bob have agreed to use this key.
let key = SymmetricKey()

// Alice signs a plaintext message, then encrypts it.
let innerSignedEnvelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)
let envelope = Envelope(inner: innerSignedEnvelope, key: key)

// Bob decrypts the outer envelope using the shared key.
guard
    let innerEnvelope = envelope.inner(with: key)
else {
    XCTFail()
    return
}
// Bob validates Alice's signature.
XCTAssertTrue(innerEnvelope.hasValidSignature(from: Self.alicePeer))
// Bob reads the message.
XCTAssertEqual(innerEnvelope.plaintext, Self.plaintext)
```

#### Schematic

> "An encrypted envelope containing a signed envelope."

```
Envelope {
    Message {           |
        Envelope {      |
            Plaintext   | ENCRYPTED
            Signature   |
        }               |
    }                   |
    Permit: symmetric
}
```

#### CBOR Diagnostic Notation

```
49(                                                 # Envelope
   [
      2,                                            # type 2: encrypted
      48(                                           # Message
         [
            1,                                      # type 1: IETF-ChaCha20-Poly1305
            h'197c18129a299a3cc9cb538aa343580a364d88181a69f48def8948521baad542fd463d5c2c3e192d1cb0f7abdb5a687b200934f73632278f6b73df93a9b4bdd5a6d982b180db1a48357c0fca1ceeebeb3183e13b7a674d354ab4bd13e1d66987505247d7e9bc838511898ec868513bd91292d0e2057820', # ciphertext (inner signed Envelope)
            h'',                                    # aad
            h'af7dbfee763600160cc21f4d',            # nonce
            h'369e0a88152a1d172121f53e1353820f'     # auth
         ]
      ),
      702(                                          # Permt
         [1]                                        # type 1: symmetric
      )
   ]
)
```

#### Annotated CBOR

```
d8 31                                    # tag(49):         Envelope
   83                                    # array(3)
      02                                 # unsigned(2):     type 2: encrypted
      d8 30                              # tag(48):         Message
         85                              # array(5)
            01                           # unsigned(1):     type 1: IETF-ChaCha20-Poly1305
            5877                         # bytes(119):      ciphertext (inner signed Envelope)
               197c18129a299a3cc9cb538aa343580a364d88181a69f48def8948521baad542fd463d5c2c3e192d1cb0f7abdb5a687b200934f73632278f6b73df93a9b4bdd5a6d982b180db1a48357c0fca1ceeebeb3183e13b7a674d354ab4bd13e1d66987505247d7e9bc838511898ec868513bd91292d0e2057820
            40                           # bytes(0):        aad
            4c                           # bytes(12):       nonce
               af7dbfee763600160cc21f4d
            50                           # bytes(16):       auth
               369e0a88152a1d172121f53e1353820f
      d9 02be                            # tag(702):        Permit
         81                              # array(1)
            01                           # unsigned(1):     type 1: symmetric
```

#### UR

```
ur:crypto-envelope/lsaotpdylpadhdktcfkecsbgnydtnyfnsosbguleotfxhdbkengtlocscyinwklgwsldfdgmcwpktlfwzcfgfshhdwfmcfdpcepfylpyuyhtiskgcxaseeyleneydimyjejkurmuptqzrytloltalfpalauycyfdeckebssgcewywmwmehlsvyfrkniogtecgeqzrybwvytbinltgdgmfltswlrflslpbyldmnspisgyfrtabgmotivoahkscxfzgspekirswykoenaecmbnsactgtgdennnbklobzdrcachclclykfmbwgulfbstaaornlyaddpaxmyol
```

### Example 6: Encrypt-Then-Sign

```swift
// Alice and Bob have agreed to use this key.
let key = SymmetricKey()

// Alice encrypts a message, then signs it.
let innerEncryptedEnvelope = Envelope(plaintext: Self.plaintext, key: key)
let envelope = Envelope(inner: innerEncryptedEnvelope, signer: Self.aliceIdentity)

// Bob checks the signature of the outer envelope, then decrypts the inner envelope.
guard
    envelope.hasValidSignature(from: Self.alicePeer),
    let plaintext = envelope.inner?.plaintext(with: key)
else {
    XCTFail()
    return
}

// Bob reads the message.
XCTAssertEqual(plaintext, Self.plaintext)
```

#### Schematic

> "A signed envelope containing an encrypted envelope."

```
Envelope {
    Plaintext {
        Envelope {
            Message {           |
                Plaintext       | ENCRYPTED
            }                   |
            Permit: symmetric   |
        }
    }
    Signature
}
```

#### CBOR Diagnostic Notation

```
49(                     # Envelope
   [
      1,                # type 1: Plaintext (inner encrypted Envelope)
      h'd8318302d83085015829e42bfc2635ebcc35fdb81bc2036105c1c0552f0be88194f9e3f6358aa6461afe3d4aeacca6bb5b0ca7404cdcef0a8aef2bfe6faf1b7050503f1f06484a23d01d5843b843fc18c602d902be8101',
      [
         707(           # Signature
            [
               1,       # type 1: EdDSA-25519
               h'4ad16a349e529f23b845db8d73d33c20101411322939e6e77388bdcaf01425381e4cecb64556b475543a68fac43dcfed2124783c80fb48d1247564874491ce02'
            ]
         )
      ]
   ]
)
```

#### Annotated CBOR

```
d8 31                                    # tag(49):         Envelope
   83                                    # array(3)
      02                                 # unsigned(2):     type 2: encrypted
      d8 30                              # tag(48):         Message
         85                              # array(5)
            01                           # unsigned(1):     type 1: IETF-ChaCha20-Poly1305
            5877                         # bytes(119):      ciphertext (inner encrypted Envelope)
               197c18129a299a3cc9cb538aa343580a364d88181a69f48def8948521baad542fd463d5c2c3e192d1cb0f7abdb5a687b200934f73632278f6b73df93a9b4bdd5a6d982b180db1a48357c0fca1ceeebeb3183e13b7a674d354ab4bd13e1d66987505247d7e9bc838511898ec868513bd91292d0e2057820
            40                           # bytes(0):        aad
            4c                           # bytes(12):       nonce
               af7dbfee763600160cc21f4d
            50                           # bytes(16):       auth
               369e0a88152a1d172121f53e1353820f
      d9 02be                            # tag(702):        Permit
         81                              # array(1)
            01                           # unsigned(1):     type 1: symmetric
```

#### UR

```
ur:crypto-envelope/lsaotpdylpadhdktcfkecsbgnydtnyfnsosbguleotfxhdbkengtlocscyinwklgwsldfdgmcwpktlfwzcfgfshhdwfmcfdpcepfylpyuyhtiskgcxaseeyleneydimyjejkurmuptqzrytloltalfpalauycyfdeckebssgcewywmwmehlsvyfrkniogtecgeqzrybwvytbinltgdgmfltswlrflslpbyldmnspisgyfrtabgmotivoahkscxfzgspekirswykoenaecmbnsactgtgdennnbklobzdrcachclclykfmbwgulfbstaaornlyaddpaxmyol
```

### Example 7: Multi-Recipient Encryption

```swift
// Alice encrypts a message so that it can only be decrypted by Bob or Carol.
let envelope = Envelope(plaintext: Self.plaintext, recipients: [Self.bobPeer, Self.carolPeer])

// Bob decrypts and reads the message.
XCTAssertEqual(envelope.plaintext(for: Self.bobIdentity), Self.plaintext)

// Carol decrypts and reads the message.
XCTAssertEqual(envelope.plaintext(for: Self.carolIdentity), Self.plaintext)

// Alice didn't encrypt it to herself, so she can't read it.
XCTAssertNil(envelope.plaintext(for: Self.aliceIdentity))
```

#### Schematic

> "An envelope that can only be opened by specific receivers."

```
Envelope {
    Message {       |
        Plaintext   | ENCRYPTED
    }               |
    Permit: recipients {
        [SealedMessage, SealedMessage]
    }
}
```

#### CBOR Diagnostic Notation

```
49(                                                             # Envelope
   [
      2,                                                        # type 2: encrypted
      48(                                                       # Message
         [
            1,                                                  # type 1: IETF-ChaCha20-Poly1305
            h'8b734943d87885b801590b7725ad5a26d6d63cd4231a3b70264db9f36c68af4db862ca2fbb885439a6', # ciphertext (content)
            h'',                                                # aad
            h'56e9ed5e21e08a2653525a02',                        # nonce
            h'aa3bb5e87814f23072f7db369e52a8ec'                 # auth
         ]
      ),
      702(                                                      # Permit
         [
            2,                                                  # type 2: recipients
            [
               55(                                              # SealedMessage
                  [
                     1,                                         # type 1
                     48(                                        # Message
                        [
                           1,                                   # type 1: IETF-ChaCha20-Poly1305
                           h'f54942628db46053ce626c5e29f3d69d23db588da34ec885c757ef8c54f93d54', # ciphertext (content key)
                           h'',                                 # aad
                           h'673b2db726a2e70eff3c9eae',         # nonce
                           h'56924591b64575a14b4a70513378eb2d'  # auth
                        ]
                     ),
                     705(                                       # ephemeralPublicKey: X25519 PublicAgreementKey
                        h'3886089f2aabcae11700b61931219523c48b4dcbe788c7f981441b5df2eaa45a'
                     )
                  ]
               ),
               55(                                              # SealedMessage
                  [
                     1,                                         # type 1
                     48(                                        # Message
                        [
                           1,                                   # type 1: IETF-ChaCha20-Poly1305
                           h'6f2195f3ae69430c0229a348b2647d660c13b39f723b8786a8ca8bc458ea213b', # ciphertext (content key)
                           h'',                                 # aad
                           h'f1192359657e580f05708c5d',         # nonce
                           h'f4db001c6bfc299359da4695cbac6399'  # auth
                        ]
                     ),
                     705(                                       # ephemeralPublicKey: X25519 PublicAgreementKey
                        h'6a44d9297185b3111b6293897dfece0c6702990fba188336bed0bc9e3e87e904'
                     )
                  ]
               )
            ]
         ]
      )
   ]
)
```

#### Annotated CBOR

```
d8 31                                    # tag(49):             Envelope
   83                                    # array(3)
      02                                 # unsigned(2):         type 2: encrypted
      d8 30                              # tag(48):             Message
         85                              # array(5)
            01                           # unsigned(1):         type 1: IETF-ChaCha20-Poly1305
            5829                         # bytes(41):           ciphertext (content)
               8b734943d87885b801590b7725ad5a26d6d63cd4231a3b70264db9f36c68af4db862ca2fbb885439a6
            40                           # bytes(0):            aad

            4c                           # bytes(12):           nonce
               56e9ed5e21e08a2653525a02
            50                           # bytes(16):           auth
               aa3bb5e87814f23072f7db369e52a8ec
      d9 02be                            # tag(702):            Permit
         82                              # array(2)
            02                           # unsigned(2):         type 2: recipients
            82                           # array(2)
               d8 37                     # tag(55):             SealedMessage
                  83                     # array(3)
                     01                  # unsigned(1):         type 1
                     d8 30               # tag(48):             Message
                        85               # array(5)
                           01            # unsigned(1):         type 1: IETF-ChaCha20-Poly1305
                           5820          # bytes(32):           ciphertext (content key)
                              f54942628db46053ce626c5e29f3d69d23db588da34ec885c757ef8c54f93d54
                           40            # bytes(0):            aad

                           4c            # bytes(12):           nonce
                              673b2db726a2e70eff3c9eae
                           50            # bytes(16):           auth
                              56924591b64575a14b4a70513378eb2d
                     d9 02c1             # tag(705):            ephemeralPublicKey: X25519 PublicAgreementKey
                        5820             # bytes(32)
                           3886089f2aabcae11700b61931219523c48b4dcbe788c7f981441b5df2eaa45a
               d8 37                     # tag(55):            SealedMessage
                  83                     # array(3)
                     01                  # unsigned(1):         type 1
                     d8 30               # tag(48):             Message
                        85               # array(5)
                           01            # unsigned(1):         type 1: IETF-ChaCha20-Poly1305
                           5820          # bytes(32):           ciphertext (content key)
                              6f2195f3ae69430c0229a348b2647d660c13b39f723b8786a8ca8bc458ea213b
                           40            # bytes(0):            aad

                           4c            # bytes(12):           nonce
                              f1192359657e580f05708c5d
                           50            # bytes(16):           auth
                              f4db001c6bfc299359da4695cbac6399
                     d9 02c1             # tag(705):            ephemeralPublicKey: X25519 PublicAgreementKey
                        5820             # bytes(32)
                           6a44d9297185b3111b6293897dfece0c6702990fba188336bed0bc9e3e87e904
```

#### UR

```
ur:crypto-envelope/lsaotpdylpadhddtlujkgafxtpkslproadhkbdktdapmhtdstbtbfntycncyfrjodsgtrhwfjzispegtroidsgdlrkloghesolfzgshfwlwehyclvtledsgugmhtaogdpkfrrevsksbbwzdyjpyluyennngmpdwptaaornlfaolftpemlsadtpdylpadhdcxykgafwidlgqzhngutoidjzhydtwftbntcnuyhdlgotglsplpsthgwslkghytfsghfzgsiofrdprldsoevdbazmfnnnplgdhfmofemerpfekpoygrgejogyeokswmdptaaosehdcxetlnaynedrpysgvychaerpcfehclmdcnsslugtsbvdlostytlyfycwhlwzwdoxhttpemlsadtpdylpadhdcxjlclmdwfplinfxbnaodtotfdpriekiiybnbwqdnejpfrltlnpdsglusshdwdclfrfzgswncfcnhkihkbhdbsahjolkhlgdwkuyaecejeztdtmuhktnfgmdsbpsianltaaosehdcximfytadtjslpqdbycwidmuldkizetobnioaonlbsrdcslsenrntirfnnfmltwlaajljswmtt
```

### Example 8: Signed Multi-Recipient Encryption

```swift
// Alice signs a message, and then encrypts it so that it can only be decrypted by Bob or Carol.
let innerSignedEnvelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)
let envelope = Envelope(inner: innerSignedEnvelope, recipients: [Self.bobPeer, Self.carolPeer])

// Bob decrypts the outer envelope using his identity.
guard
    let innerEnvelope = envelope.inner(for: Self.bobIdentity)
else {
    XCTFail()
    return
}
// Bob validates Alice's signature.
XCTAssertTrue(innerEnvelope.hasValidSignature(from: Self.alicePeer))
// Bob reads the message.
XCTAssertEqual(innerEnvelope.plaintext, Self.plaintext)
```

#### Schematic

> "A signed envelope that can only be opened by specific receivers."

```
Envelope {
    Message {               |
        Envelope {          |
            Plaintext       | ENCRYPTED
            Signature       |
        }                   |
    }                       |
    Permit: recipients {
        [SealedMessage, SealedMessage]
    }
}
```

#### CBOR Diagnostic Notation

```
49(                                                             # Envelope
   [
      2,                                                        # type 2: encrypted
      48(                                                       # Message
         [
            1,                                                  # type 1: IETF-ChaCha20-Poly1305
            h'509450c376223dc148e8f6e0ee0740b21914320b91345f1efca8b23782657d89f649928c9c4161bb3cd18099b87a465c7d21ecce1c7c6706b2f03f8feca4c0ee9dedf4c9064342ee3c9dd47cbf98d9c7ce5af824d8d5176a8c7ec7103c5b05b192f20d1bc6d5f9e54dcfba32cc059d6ebe47bf9be1152b', # ciphertext (inner signed envelope)
            h'',                                                # aad
            h'4d5ba54df20df2da8cfebd00',                        # nonce
            h'9e29178f851ea967b1ef59ce9eb930f4'                 # auth
         ]
      ),
      702(                                                      # Permit
         [
            2,                                                  # type 2: recipients
            [
               55(                                              # SealedMessage
                  [
                     1,                                         # type 1
                     48(                                        # Message
                        [
                           1,                                   # type 1: IETF-ChaCha20-Poly1305
                           h'8b47f3d0aaa918b50a4bc19e21fdb64119a31181952d94dd2da543c4343e1cd0', # ciphertext (content key)
                           h'',                                 # aad
                           h'd98b5b8fb33a144d6c234d30',         # nonce
                           h'791f9246de04e0ead050a09ffaf11588'  # auth
                        ]
                     ),
                     705(                                       # ephemeralPublicKey: X25519 PublicAgreementKey
                        h'e7e14836146e9ec45d2aaa634284c2e3c78e650554c2571fec9ccf2f6ab27d7f'
                     )
                  ]
               ),
               55(                                              # SealedMessage
                  [
                     1,                                         # type 1
                     48(                                        # Message
                        [
                           1,                                   # type 1: IETF-ChaCha20-Poly1305
                           h'd593e3126c98bc8f05f4ded74a5c608c809bc6e565377d8a8793634607b241f0', # ciphertext (content key)
                           h'',                                 # aad
                           h'15281c1216e6d71cab83cfdd',         # nonce
                           h'89f355a11bc949e82e4186dd2253e1bd'  # auth
                        ]
                     ),
                     705(                                       # ephemeralPublicKey: X25519 PublicAgreementKey
                        h'799b83e3298186f40d4548f92715258b27f29d8d8087d7ea61092f0f89880a01'
                     )
                  ]
               )
            ]
         ]
      )
   ]
)
```

#### Annotated CBOR

```
d8 31                                    # tag(49):                         Envelope
   83                                    # array(3)
      02                                 # unsigned(2):                     type 2: encrypted
      d8 30                              # tag(48):                         Message
         85                              # array(5)
            01                           # unsigned(1):                     type 1: IETF-ChaCha20-Poly1305
            5877                         # bytes(119):                      ciphertext (inner signed envelope)
               509450c376223dc148e8f6e0ee0740b21914320b91345f1efca8b23782657d89f649928c9c4161bb3cd18099b87a465c7d21ecce1c7c6706b2f03f8feca4c0ee9dedf4c9064342ee3c9dd47cbf98d9c7ce5af824d8d5176a8c7ec7103c5b05b192f20d1bc6d5f9e54dcfba32cc059d6ebe47bf9be1152b
            40                           # bytes(0):                        aad
            4c                           # bytes(12):                       nonce
               4d5ba54df20df2da8cfebd00
            50                           # bytes(16):                       auth
               9e29178f851ea967b1ef59ce9eb930f4
      d9 02be                            # tag(702):                        Permit
         82                              # array(2)
            02                           # unsigned(2):                     type 2: recipients
            82                           # array(2)
               d8 37                     # tag(55):                         SealedMessage
                  83                     # array(3)
                     01                  # unsigned(1):                     type 1
                     d8 30               # tag(48):                         Message
                        85               # array(5)
                           01            # unsigned(1):                     type 1: IETF-ChaCha20-Poly1305
                           5820          # bytes(32):                       ciphertext (content key)
                              8b47f3d0aaa918b50a4bc19e21fdb64119a31181952d94dd2da543c4343e1cd0
                           40            # bytes(0):                        aad
                           4c            # bytes(12):                       nonce
                              d98b5b8fb33a144d6c234d30
                           50            # bytes(16):                       auth
                              791f9246de04e0ead050a09ffaf11588
                     d9 02c1             # tag(705):                        ephemeralPublicKey: X25519 PublicAgreementKey
                        5820             # bytes(32)
                           e7e14836146e9ec45d2aaa634284c2e3c78e650554c2571fec9ccf2f6ab27d7f
               d8 37                     # tag(55):                         SealedMessage
                  83                     # array(3)
                     01                  # unsigned(1):                     type 1
                     d8 30               # tag(48):                         Message
                        85               # array(5)
                           01            # unsigned(1):                     type 1: IETF-ChaCha20-Poly1305
                           5820          # bytes(32):                       ciphertext (content key)
                              d593e3126c98bc8f05f4ded74a5c608c809bc6e565377d8a8793634607b241f0
                           40            # bytes(0):                        aad
                           4c            # bytes(12):                       nonce
                              15281c1216e6d71cab83cfdd
                           50            # bytes(16):                       auth
                              89f355a11bc949e82e4186dd2253e1bd
                     d9 02c1             # tag(705):                        ephemeralPublicKey: X25519 PublicAgreementKey
                        5820             # bytes(32)
                           799b83e3298186f40d4548f92715258b27f29d8d8087d7ea61092f0f89880a01
```

#### UR

```
ur:crypto-envelope/lsaotpdylpadhdktgdmwgdsrkocpfssefdvsynvtwyatfzprcfbbeybdmeeeheckztpdpremlfihkildyngamolknsfphsrkfnttlanlroknfghhkiclwptocekeioamprwtfhmywpoxrtwyntwewksoamfxfwwyfnnttykersmktasttohtyadktptlchimlkkbstbefnhpahpamowzbtcwswtlytvwgttkrdeysfahntjtrnflrsndvybzdnfzgsgthpongtwzbtwztnlkzeryaegdnndtchmylpckptiopawshktonnrhdywktaaornlfaolftpemlsadtpdylpadhdcxluflwftipkptcsrebkgrsennclzcrpfpcfotbylymddpmwutdponfxsseefmcetifzgstaluhpmyqdftbbgtjzcngtdygdkkctmofgueaavtwdtigdnbnezswnbzlotaaosehdcxvdvyfdenbbjtnnsshldrpkiafwlrsavlstmnihahghsahgctwpnstkdlimprkilbtpemlsadtpdylpadhdcxtlmuvlbgjzmkrfmyahwkuetsgehhhnlklandswvwihemkileltmuiafgatprfpwtfzgsbzdecebgcmvatscepylstkutgdldwfgooycwsogavsdmfplnutcpguvyrytaaosehdcxkkndlsvldtlylnwkbtfefdytdibzdaludiwzntlglalttswdhsasdlbsldlobkadwdtyrtfy
```

### Example 9: Sharding a Secret using SSKR

```swift
// Dan has a cryptographic seed he wants to backup using a social recovery scheme.
// The seed includes metadata he wants to back up also, making it too large to fit
// into a basic SSKR share.
var danSeed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
danSeed.name = "Dark Purple Aqua Love"
danSeed.creationDate = try! Date("2021-02-24T00:00:00Z", strategy: .iso8601)
danSeed.note = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

// Dan splits the seed into a single group 2-of-3. This returns an array of arrays
// of Envelope, the outer arrays representing SSKR groups and the inner array
// elements each holding the encrypted seed and a single share.
let envelopes = Envelope.split(plaintext: danSeed.taggedCBOR, groupThreshold: 1, groups: [(2, 3)])

// Flattening the array of arrays gives just a single array of all the envelopes to be distributed.
let sentEnvelopes = envelopes.flatMap { $0 }

// Dan sends one envelope to each of Alice, Bob, and Carol.

// let aliceEnvelope = sentEnvelopes[0] // UNRECOVERED
let bobEnvelope = sentEnvelopes[1]
let carolEnvelope = sentEnvelopes[2]

// At some future point, Dan retrieves two of the three envelopes so he can recover his seed.
let recoveredEnvelopes = [bobEnvelope, carolEnvelope]
let recoveredSeed = try Seed(taggedCBOR: Envelope.plaintext(from: recoveredEnvelopes)!)

// The recovered seed is correct.
XCTAssertEqual(danSeed.data, recoveredSeed.data)
XCTAssertEqual(danSeed.creationDate, recoveredSeed.creationDate)
XCTAssertEqual(danSeed.name, recoveredSeed.name)
XCTAssertEqual(danSeed.note, recoveredSeed.note)

// Attempting to recover with only one of the envelopes won't work.
XCTAssertNil(Envelope.plaintext(from: [bobEnvelope]))
```

#### Schematic

> "Several envelopes containing a seed split into several SSKR shares."

```
Envelope 0 {
    Message {       |
        Seed        | ENCRYPTED
    }               |
    Permit: sskr {
        SSKRShare 0
    }
}

Envelope 1 {
    Message {       |
        Seed        | ENCRYPTED
    }               |
    Permit: sskr {
        SSKRShare 1
    }
}

Envelope 2 {
    Message {       |
        Seed        | ENCRYPTED
    }               |
    Permit: sskr {
        SSKRShare 2
    }
}
```

#### CBOR Diagnostic Notation

These examples detail one of the three envelopes.

```
49(                                                             # Envelope
   [
      2,                                                        # type 2: encrypted
      48(                                                       # Message
         [
            1,                                                  # type 1: IETF-ChaCha20-Poly1305
            h'435d087a18450c875e5080539362379e759734a6b6a585e0a7bf04be37459e5b26f90cf1a9c40e2bdd18c6119253a41f76e835636314e816c1ae29d2cedb9726059f3c6cf0bba00818d0d31ce8a976207a15b6b772171d73b4e1c7fcf951576df748f38a27201cbf7a427bafe2ac5a5e1dde688882172fefb6d226c54ee5c2a5e4e073e5217efac9ef8787f47364cde5401c32dc0ca5232448c7bc28e20cc59bc158c18d0239d1847b85d900d5151ac0af04',
            h'',                                                # aad
            h'12516606a3ac65bd8ec0c183',                        # nonce
            h'dde474a4f45ad8d505fc583d2070352c'                 # auth
         ]
      ),
      702(                                                      # Permit
         [
            3,                                                  # type 3: SSKR
            309(                                                # SSKRShare
               h'cc68000101a664536ca2f9a3df90e855bcf3ce90e8859f690f1381c83a67761b17e0545a11'
            )
         ]
      )
   ]
)
```

#### Annotated CBOR

```
d8 31                                    # tag(49):             Envelope
   83                                    # array(3)
      02                                 # unsigned(2):         type 2: encrypted
      d8 30                              # tag(48):             Message
         85                              # array(5)
            01                           # unsigned(1):         type 1: IETF-ChaCha20-Poly1305
            58b2                         # bytes(178):          ciphertext (Seed)
               435d087a18450c875e5080539362379e759734a6b6a585e0a7bf04be37459e5b26f90cf1a9c40e2bdd18c6119253a41f76e835636314e816c1ae29d2cedb9726059f3c6cf0bba00818d0d31ce8a976207a15b6b772171d73b4e1c7fcf951576df748f38a27201cbf7a427bafe2ac5a5e1dde688882172fefb6d226c54ee5c2a5e4e073e5217efac9ef8787f47364cde5401c32dc0ca5232448c7bc28e20cc59bc158c18d0239d1847b85d900d5151ac0af04
            40                           # bytes(0):            aad

            4c                           # bytes(12):           nonce
               12516606a3ac65bd8ec0c183
            50                           # bytes(16):           auth
               dde474a4f45ad8d505fc583d2070352c
      d9 02be                            # tag(702):            Permit
         82                              # array(2)
            03                           # unsigned(3):         type 3: SSKR
            d9 0135                      # tag(309):            SSKRShare
               5825                      # bytes(37)
                  cc68000101a664536ca2f9a3df90e855bcf3ce90e8859f690f1381c83a67761b17e0545a11
```

```
ur:crypto-envelope/lsaotpdylpadhdprfxhlaykncsfebnlthygdlagumuidemnnkpmseeolrponlpvtosrsaarnemfennhpdsytbnwnptssbadnutcsswbymoguoxctkovseciaiabbvscmsepldttdtouymsdsahnefnjzwtrknbaycstitecevsptkocxknbzrprljpchcajkqzvystztytgyhgjnylfdwfledicxcersknfwkgpevopshthycaueislolfchdlwsrptddsskglvwsaonvevtjkvwclkbzssowsltltwkjkiesnvwfzceeyuobnoncndkfdstrfdevobnskndsehdselgaoesttlrkglptaaetlbzcyrtpeaafzgsbggyiyamotpsihrymnrtselsgdutvejyoxwkhttptlahzthdfscxjoecdwtaaornlfaxtaadechddasfisaeadadoliegujzoeytoturmhvsgorfwftomhvslpneinbsbwlyspftiokocwchvtghhtbydlvedleh
```
