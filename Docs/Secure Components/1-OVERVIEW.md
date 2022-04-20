# Secure Components - Overview

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** March 28, 2022</br>
**Status:** DRAFT

---

## Contents

* Overview: This document.
* [Examples](2-EXAMPLES.md)
* [Definitions](3-DEFINITIONS.md)

---

## Introduction

The Secure Components suite provides tools for easily implementing encryption (symmetric or public key), signing, and sharding of messages, including serialization to and from [CBOR](https://cbor.io/), and [UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md) formats.

## Status

**DRAFT.** There is a reference implementation in [BCSwiftFoundation](https://github.com/blockchaincommons/BCSwiftFoundation), but everything is still fluid and subject to change.

**⚠️ WARNING:** As of the date of this publication the CBOR tags in the range `48` through `51` and `55` are currently unallocated in the [IANA Registry of CBOR Tags](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml). Blockchain Commons is applying for these number to be assigned to the CBOR specification herein, but because these numbers are in a range that is open to other applications, it may change. For now, these low-numbered tags MUST be understood as provisional and subject to change by all implementors.

## Goals

The goal is to create a general purpose, composable suite of data types that:

* Are based on object-centric architecture
* Make it easy to represent common encryption constructions
* Are based on algorithms and constructs that are considered best practices.
* Allow for the future extension of functionality to include additional cryptographic algorithms and methods.
* Represent structured data using [CBOR](https://cbor.io/) and [UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md).
* Support innovative constructs like [Sharded Secret Key Reconstruction (SSKR)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md).
* Interoperate with structures of particular interest to blockchain and cryptocurrency developers, such as [seeds](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md#cryptographic-seed-crypto-seed) and [HD keys](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md).
* Support protocols like [Distributed Identifiers](https://www.w3.org/TR/did-core/).
* Support complex metadata (assertions about assertions).
* Support semantic knowledge graphs.
* Support mutable and immutable architectures.
* Provide a reference API implementation in Swift that is easy to use and hard to abuse.

Other goals we are considering include:

* Support eventual consistency using [conflict-free replicated datatypes (CRDTs)](https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type)
* Minimize opportunities for correlation without first demonstrating ability to decrypt or provide an adapter signature.
* Correlation resistance leveraging similarities between UUIDs, nonces, hashes, content addressable hashes, signatures, etc.
* Focus first on peer-based, web-of-trust, self-sovereign key models for roots of trust, where peers may be groups.
* Support “Progressive Trust” models:
    * Progressive trust is the ability of an individual to gradually increase the amount of relevant data revealed as trust is built or value generated.
    * [W3C Data Minimization](https://w3c-ccg.github.io/data-minimization/#progressive-trust)
    * [Original concept](http://www.lifewithalacrity.com/2004/08/progressive_tru.html)
* Default and fundamental support of aggregated group multisig signatures, in particular prime-order curves like secp256k1, or point-compressed cofactor solutions like [ristretto255](https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-00.html):
    * Reason? Multisig attacks:
        * [Prime, Order Please! - Revisiting Small Subgroup and Invalid Curve Attacks on Protocols using Diffie-Hellman](https://eprint.iacr.org/2019/526.pdf)
        * [Cofactor Explained: Clearing Elliptic Curves' dirty little secret](https://loup-vaillant.fr/tutorials/cofactor)
        * [Attack on Monero using 25519](https://jonasnick.github.io/blog/2017/05/23/exploiting-low-order-generators-in-one-time-ring-signatures/)
* Fundamental support for redactable signatures, possibly:
    * Bauer, Blough, Cash - [Minimal Information Disclosure with Efficiently Verifiable Credentials](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.153.8662&rep=rep1&type=pdf)
* Support for various modern techniques like signature aggregation (Musig2 m of m), threshold signatures (FROST n of m), adapter signatures, scriptless scripts, discrete log contracts, Brandian blind signatures (and improvements), smart signature scripts, distributed key generation & verifiable secret sharing

---

## Top-Level Types

The types defined in the Secure Components suite are designed to be minimal, simple to use, and composable. They can all be used independently, but are designed to work together. Here is a quick summary of these types:

* `Simplex` is the central "top level" type of Secure Components. It is a "simple container for complex concepts" supporting everything from enclosing the most basic of plaintext messages, to innumerable recursive permutations of encryption, signing, sharding, and representing semantic graphs.
* `EncryptedMessage` is a symmetrically-encrypted message and is specified in full in [BCR-2022-001](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-001-secure-message.md).
* `PrivateKeyBase` holds key material such as a Seed belonging to an identifiable entity, and can produce all the private and public keys needed to use this suite. It is usually only serialized for purposes of backup.
* `PublicKeyBase` holds the public keys of an identifiable entity, and can be made public. It is not simply called a "public key" because it holds at least _two_ public keys: one for signing and another for encryption.
* `SealedMessage` is a message that has been one-way encrypted to a specific `PublicKeyBase`, and is used to implement multi-recipient public key encryption using `Envelope`.
* `Digest` is a cryptographic hash that uniquely identifies an immutable binary object.
* `SCID` is a "self-certifying identifier" that uniquely identifies a mutable set of traits.

Many of the types defined herein are assigned CBOR tags for use when encoding these structures. The types in this section may be used embedded within larger structures as tagged CBOR, or as top-level objects in URs. Note that when encoding URs, a top-level CBOR tag is not used, as the UR type provides that information.

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|48|`crypto-msg`|`EncryptedMessage`|
|49|`crypto-simplex`|`Simplex`|
|50|`crypto-prvkeys`|`PrivateKeyBase`|
|51|`crypto-pubkeys`|`PublicKeyBase`|
|55|`crypto-sealed`|`SealedMessage`|
|56|`crypto-digest`|`Digest`|
|57|`crypto-key`|`SymmetricKey`|
|58|`crypto-scid`|`SCID`|

## Tagged Types

Types that do not define a UR type generally would never be serialized as a top-level object, but are frequently serialized as part of a larger structure. The `Predicate` type has a single-byte CBOR tag due to its frequency of use in the `Simplex` type.

|CBOR Tag|Swift Type|
|---|---|
|59|`Predicate`|
|700|`Password`|
|701|`Permit`|
|702|`AgreementPrivateKey`|
|703|`AgreementPublicKey`|
|704|`SigningPrivateKey`|
|705|`SigningPublicKey`|
|706|`Signature`|
|707|`Nonce`|

## Untagged Types

A number of types are simply serialized as untagged CBOR byte strings. They do not need tags because they are used in contexts where their meaning is fixed and unlikely to change over time. These include:

* `AAD`
* `Auth`
* `Ciphertext`
* `Plaintext`
* `Salt`
* `Tag`

For example, a field called `Auth` is currently only used in the context of the IETF-ChaCha20-Poly1305 encryption algorithm, and therefore does not need to be specifically tagged. If another algorithm also needed a field called `Auth`, it would be used in the context of *that* algorithm, and the two fields would not be considered interchangeable.

## Algorithms

The algorithms that Secure Components currently incorporates are listed below. The components include provisions for the future inclusion of additional algorithms and methods.

* **Hashing:** [Blake2b](https://datatracker.ietf.org/doc/rfc7693)
* **Signing:** [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) or [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137)
* **Symmetric Encryption:** [IETF-ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)
* **Public Key Encryption:** [X25519](https://datatracker.ietf.org/doc/html/rfc7748)
* **Key Derivation**: [HKDF-SHA-512](https://datatracker.ietf.org/doc/html/rfc5869)
* **Password-Based Key Derivation**: [scrypt](https://datatracker.ietf.org/doc/html/rfc7914)
* **Sharding**: [SSKR (Sharded Secret Key Reconstruction)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md)

## Overview of the Simplex Type

A `Simplex` is a "simple container for complex concepts" supporting everything from enclosing the most basic of plaintext messages, to innumerable recursive permutations of encryption, signing, sharding, and representing semantic graphs. Here is its definition in Swift:

```swift
public struct Simplex {
    public let subject: Subject
    public let assertions: [Assertion]
}
```

The basic idea is that a `Simplex` contains some [deterministically-encoded CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#name-deterministically-encoded-c) data (the `subject`) that may or may not be encrypted, and zero or more assertions about the `subject`.

It is an enumerated type with two cases: `.plaintext` and `.encrypted`.

* If `.plaintext` is used, it may also carry one or more signatures.
* If `.encrypted` is used, the `EncryptedMessage` is accompanied by a `Permit` that defines the conditions under which the `EncryptedMessage` may be decrypted.

To facilitate further decoding, it is RECOMMENDED that the payload of an `Envelope` should itself be tagged CBOR.

`Envelope` may contain as its payload another CBOR-encoded `Envelope`. This facilitates various constructions, including sign-then-encrypt and encrypt-then sign.

The reason why `.plaintext` messages may be signed and `.encrypted` messages may not is that generally a signer should have access to the content of what they are signing, therefore this design encourages the sign-then-encrypt order of operations. If encrypt-then-sign is preferred, then this is easily accomplished by creating an `.encrypted` and then enclosing that envelope in a `.plaintext` with the appropriate signatures.

A `Permit` specifies the conditions under which an `EncryptedMessage` may be decrypted, and contains three cases:

```swift
public enum Permit {
    case symmetric
    case recipients([SealedMessage])
    case share(SSKRShare)
}
```

* `.symmetric` means that the `EncryptedMessage` was encrypted with a `SymmetricKey` that the receiver is already expected to have.
* `.recipients` facilitates multi-recipient public key cryptography by including an array of `SealedMessage`, each of which is encrypted to a particular recipient's public key, and which contains an ephemeral key that can be used by a recipient to decrypt the main message.
* `.share` facilitates social recovery by pairing an `EncryptedMessage` encrypted with an ephemeral key with an `SSKRShare`, and providing for the production of a set of `Envelope`s, each one including a different share. Only an M-of-N threshold of shares will allow the recovery of the ephemeral key and hence the decryption of the original message. Each recipient of one of these `Envelope`s will have an encrypted backup of the entire original `EncryptedMessage`, but only a single `SSKRShare`.

This structure provides a flexible framework for constructing solutions for various applications. Here are some high-level schematics of such applications. See the EXAMPLES chapter for more detail.

### "An envelope containing plaintext."

```mermaid
graph TD
    subgraph Envelope
        subgraph plaintext
            payload
            subgraph signatures
            end
        end
    end
style payload fill:#0000
style plaintext fill:#0000
style Envelope fill:#0000, stroke: #88f, stroke-width: 3
style signatures fill:#0000, stroke-dasharray: 5 5
```

### "An envelope containing signed plaintext."

```mermaid
graph TD
    subgraph Envelope
        subgraph plaintext
            payload
            subgraph signatures
                signature0
            end
        end
    end
style payload fill:#0000
style signature0 fill:#0000
style plaintext fill:#0000
style Envelope fill:#0000, stroke: #88f, stroke-width: 3
style signatures fill:#0000
```

### "An envelope containing plaintext signed by several parties."

```mermaid
graph TD
    subgraph Envelope
        subgraph plaintext
            payload
            subgraph signatures
                signature0
                signature1
            end
        end
    end
style payload fill:#0000
style signature0 fill:#0000
style signature1 fill:#0000
style plaintext fill:#0000
style Envelope fill:#0000, stroke: #88f, stroke-width: 3
style signatures fill:#0000
```

### "An envelope containing an encrypted message."

```mermaid
graph TD
    subgraph Envelope
        subgraph encrypted
            subgraph EncryptedMessage
                payload
            end
            subgraph Permit
                symmetric
            end
        end
    end
style payload fill:#0000
style EncryptedMessage fill:#f002,stroke:#f00
style symmetric fill:#0000
style encrypted fill:#0000
style Envelope fill:#0000, stroke: #88f, stroke-width: 3
style Permit fill:#0000
```

### "An encrypted envelope containing a signed envelope."

```mermaid
graph TD
    subgraph Envelope1
        subgraph encrypted
            subgraph EncryptedMessage
                subgraph Envelope2
                    subgraph plaintext
                        payload
                        subgraph signatures
                            signature
                        end
                    end
                end
            end
            subgraph Permit
                symmetric
            end
        end
    end
    style payload fill:#0000
    style EncryptedMessage fill:#f002,stroke:#f00
    style symmetric fill:#0000
    style encrypted fill:#0000
    style Envelope1 fill:#0000, stroke: #88f, stroke-width: 3
    style Envelope2 fill:#0000, stroke: #88f, stroke-width: 3
    style Permit fill:#0000
    style plaintext fill:#0000
    style signatures fill:#0000
    style signature fill:#0000
```

### "A signed envelope containing an encrypted envelope."

```mermaid
graph TD
    subgraph Envelope1
        subgraph plaintext
            subgraph Envelope2
                subgraph encrypted
                    subgraph EncryptedMessage
                        payload
                    end
                    subgraph Permit
                        symmetric
                    end
                    end
                end
            subgraph signatures
              signature
            end
        end
    end
style payload fill:#0000
style signature fill:#0000
style plaintext fill:#0000
style Envelope1 fill:#0000, stroke: #88f, stroke-width: 3
style signatures fill:#0000
style Envelope2 fill:#0000, stroke: #88f, stroke-width: 3
style EncryptedMessage fill:#f002,stroke:#f00
style encrypted fill:#0000
style Permit fill:#0000
style symmetric fill:#0000
```

### "An envelope that can only be opened by specific receivers."

```mermaid
graph TD
    subgraph Envelope
        subgraph encrypted
            subgraph EncryptedMessage
                payload
            end
            subgraph Permit
                subgraph recipients
                    SealedMessage1
                    SealedMessage2
                end
            end
        end
    end
style payload fill:#0000
style EncryptedMessage fill:#f002,stroke:#f00
style SealedMessage1 fill:#0000
style SealedMessage2 fill:#0000
style encrypted fill:#0000
style Envelope fill:#0000, stroke: #88f, stroke-width: 3
style Permit fill:#0000
style recipients fill:#0000
```

### "A signed envelope that can only be opened by specific receivers."

```mermaid
graph TD
    subgraph Envelope1
        subgraph encrypted
            subgraph EncryptedMessage
                subgraph Envelope2
                    subgraph plaintext
                        payload
                        subgraph signatures
                            signature
                        end
                    end
                end
            end
            subgraph Permit
                subgraph recipients
                    SealedMessage1
                    SealedMessage2
                end
            end
        end
    end
style encrypted fill:#0000
style EncryptedMessage fill:#f002,stroke:#f00
style Envelope1 fill:#0000, stroke: #88f, stroke-width: 3
style Envelope2 fill:#0000, stroke: #88f, stroke-width: 3
style payload fill:#0000
style Permit fill:#0000
style plaintext fill:#0000
style recipients fill:#0000
style SealedMessage1 fill:#0000
style SealedMessage2 fill:#0000
style signature fill:#0000
style signatures fill:#0000
```

### "Several envelopes containing a seed split into several SSKR shares."

```mermaid
graph TD
    subgraph Envelope0
        subgraph encrypted
            subgraph EncryptedMessage
                payload
            end
            subgraph Permit
                subgraph sskr
                    SSKRShare0
                end
            end
        end
    end
style payload fill:#0000
style EncryptedMessage fill:#f002,stroke:#f00
style sskr fill:#0000
style SSKRShare0 fill:#0000
style encrypted fill:#0000
style Envelope0 fill:#0000, stroke: #88f, stroke-width: 3
style Permit fill:#0000
```

```mermaid
graph TD
    subgraph Envelope1
        subgraph encrypted
            subgraph EncryptedMessage
                payload
            end
            subgraph Permit
                subgraph sskr
                    SSKRShare1
                end
            end
        end
    end
style payload fill:#0000
style EncryptedMessage fill:#f002,stroke:#f00
style sskr fill:#0000
style SSKRShare1 fill:#0000
style encrypted fill:#0000
style Envelope1 fill:#0000, stroke: #88f, stroke-width: 3
style Permit fill:#0000
```

```mermaid
graph TD
    subgraph Envelope2
        subgraph encrypted
            subgraph EncryptedMessage
                payload
            end
            subgraph Permit
                subgraph sskr
                    SSKRShare2
                end
            end
        end
    end
style payload fill:#0000
style EncryptedMessage fill:#f002,stroke:#f00
style sskr fill:#0000
style SSKRShare2 fill:#0000
style encrypted fill:#0000
style Envelope2 fill:#0000, stroke: #88f, stroke-width: 3
style Permit fill:#0000
```
