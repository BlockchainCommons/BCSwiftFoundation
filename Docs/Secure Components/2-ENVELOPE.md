# Secure Components - Overview of the Envelope Type

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** May 16, 2022</br>
**Status:** DRAFT

---

## Contents

* [Overview](1-OVERVIEW.md)
* [Envelope Overview](2-ENVELOPE.md): This document
* [Envelope Notation](3-ENVELOPE-NOTATION.md)
* [Envelope Expressions](4-ENVELOPE-EXPRESSIONS.md)
* [Definitions](5-DEFINITIONS.md)
* [Examples](6-EXAMPLES.md)

---

## Introduction

The `Envelope` type supports everything from enclosing the most basic of plaintext messages, to innumerable recursive permutations of encryption, signing, sharding, and representing semantic graphs. Here is its (slightly simplified) definition in Swift:

```swift
struct Envelope {
    let subject: Subject
    let assertions: [Assertion]
}
```

The basic idea is that an `Envelope` contains some [deterministically-encoded CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#name-deterministically-encoded-c) data (the `subject`) that may or may not be encrypted or redacted, and zero or more assertions about the `subject`.

## Subject

The `subject` of an `Envelope` is an enumerated type.

* `.leaf` represents any terminal CBOR object.
* `.envelope` represents a nested `Envelope`.
* `.encrypted` represents an `EncryptedMessage` that could be a `.leaf` or a `.envelope`.
* `.redacted` represents a value that has been elided with its place held by its `Digest`.

```swift
enum Subject {
    case leaf(CBOR)
    case envelope(Envelope)
    case encrypted(EncryptedMessage)
    case redacted(Digest)
}
```

## Assertion

`Assertion`s are `predicate`-`object` pairs that supply additional information about the `subject`.

```swift
struct Assertion {
    let predicate: Envelope
    let object: Envelope
}
```

Combining the `subject` of an `Envelope` with the `predicate` and `object` of an assertion forms a [semantic triple](https://en.wikipedia.org/wiki/Semantic_triple), which may be part of a larger [knowledge graph](https://en.wikipedia.org/wiki/Knowledge_graph):

```mermaid
graph LR
    subject:Alice --> |predicate:knows| object:Bob
```

The `predicate` and `object` are themselves `Envelope`s, and thus may also be encrypted or redacted, and may in turn contain their own assertions. It is therefore possible to hide any part of an assertion by encrypting or redacting its parts:

* You can of course hide the `subject` about which assertions are made.
* You can hide the `predicate` to reveal that the `subject` and `object` are related, but hide *how* they are related,
* You can hide the `object` to assert that the subject is related in a specific way to some other hidden object,
* You can hide every part of the assertion by hiding the `subject`, `predicate`, and `object` separately, while still revealing that an assertion *exists*,
* Finally, you can hide even the fact of the assertion's existence by encrypting or redacting a `subject` containing a `Envelope`, with its assertions hidden along with it.

It is important to understand that because `Envelope` supports "complex metadata", i.e., "assertions with assertions," users are not limited to semantic triples. Adding context, as in a [semantic quad](https://en.wikipedia.org/wiki/Named_graph#Named_graphs_and_quads), is easily accomplished with an assertion on the subject. In fact, any Envelope can also be an element of a [cons pair](https://en.wikipedia.org/wiki/Cons), with the "first" element being the `subject` and the "rest" being the assertions. And since the `subject` of an `Envelope` can be any CBOR object, a `subject` can also be any structure (such as an array or map) containing other `Envelope`s.

## Digests

Each `Envelope` produces an associated `Digest`, such that if the `subject` and `assertions` of the `Envelope` are semantically identical, then the same `Digest` must necessarily be produced.

Because hashing a concatenation of items is non-commutative, the order of the elements in the `assertions` array is determined by sorting them lexicographically by the `Digest` of each assertion, and disallowing identical assertions. This ensures that an identical `subject` with identical `assertions` will yield the same `Envelope` digest, and `Envelope`s containing other `Envelope`s will yield the same digest tree.

Envelopes can be be in several forms, for any of these forms, the same digest is present for the same binary object:

* Present locally or referenced by SCID or Digest.
* Unencrypted or encrypted.
* Unredacted or redacted.

Thus the `Digest` of an `Envelope` identifies the `subject` and its assertions as if they were all present (dereferenced), unredacted, and unencrypted. This allows an `Envelope` to be transformed either into or out of the various encrypted/decrypted, local/reference, and redacted/unredacted forms without changing the cumulative [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) of digests. This also means that any transformations that do not preserve the digest tree invalidate the signatures of any enclosing `Envelope`s.

This architecture supports selective disclosure of contents of nested `Envelope`s by revealing only the minimal objects necessary to traverse to a particular nesting path, and having done so, calculating the hashes back to the root allows verification that the correct and included contents were disclosed. On a structure where only a minimal number of fields have been revealed, a signature can still be validated.

## SCID

This proposal uses a `SCID` (Self-Certifying Identifier) type as an analogue for a [DID (Decentralized Identifier)](https://www.w3.org/TR/did-core). Both `SCID` and `Digest` may be dereferenceable through some form of distributed ledger or registry. The main difference is that the dereferenced content of a `SCID` may differ depending on what system dereferenced it or when it was dereferenced (in other words, it may be viewed as mutable), while a `Digest` always dereferences to a unique, immutable object.

Put another way, a `SCID` resolves to a *projection* of a current view of an object, while a `Digest` resolves only to a specific immutable object.

## References

In the [DID spec](https://www.w3.org/TR/did-core/), a given DID URI is tied to a single specific method for resolving it. However, there are many cases where one may want a resource (possibly a DID document-like object) or third-party assertions about such a resource to persist in a multiplicity of places, retrievable by a multiplicity of methods. Therefore, in this proposal, one or more methods for dereferencing a `SCID` or `Digest` (analogous to DID methods) may be added to an `Envelope` as assertions with the `dereferenceVia` predicate. This allows the referent to potentially exist in many places (including local caches), with the assertions providing guidance to authoritative or recommended methods for dereferencing them.

## Signatures

Signatures have a random component, so anything with a signature will have a non-deterministic (and therefore non-correlatable) digest. Therefore, the two results of signing the same object twice with the same private key will not compare as equal, even if the same binary obect was signed by the same private key. This means that each signing is a particular event that can never be repeated.
