# Secure Components - Envelope Notation

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** May 16, 2022</br>
**Status:** DRAFT

---

## Contents

* [Overview](1-OVERVIEW.md)
* [Envelope Overview](2-ENVELOPE.md)
* [Envelope Notation](3-ENVELOPE-NOTATION.md): This document
* [Envelope Expressions](4-ENVELOPE-EXPRESSIONS.md)
* [Definitions](5-DEFINITIONS.md)
* [Examples](6-EXAMPLES.md)

---

## Introduction

We provide a simplified textual notation for pretty-printing and reading instances of the `Envelope` type.

## Status

This document is a draft with a reference implementation in [BCSwiftFoundation](https://github.com/blockchaincommons/BCSwiftFoundation).

* Braces `{ }` are used to delimit the contents of a nested `Envelope`.
* Top-level braces representing the outermost `Envelope` are omitted.
* Square brackets `[ ]` may come after the `subject` of an `Envelope` and are used to delimit the list of `Assertion`s.
* Type names, enumeration cases, and empty assertion lists are elided.

For example, instead of writing:

```
{
    subject: .leaf("Hello"),
    assertions: [ ]
}
```

we simply write:

```
"Hello"
```

If we were to output the [CBOR diagnostic notation](https://www.rfc-editor.org/rfc/rfc8949.html#name-diagnostic-notation) for the above, we'd see:

```
49(
   60("Hello")
)
```

`49` is the CBOR tag for `Envelope` and `60` is the tag for `.leaf`. Wrapping this 5-byte UTF-8 string in an `Envelope` only adds 2 bytes (1 for each tag) and 1 byte that identifies the string's type and length, for a total of 8 bytes. CBOR (and hence `Envelope`) is therefore completely self-describing.

Generally, a `Envelope` output in Envelope Notation looks like this:

```
Subject [
    Predicate: Object
    Predicate: Object
    ...
]
```

The three roles `Subject`, `Predicate`, and `Object` are *themselves* Envelopes, allowing for *complex metadata*, i.e., meta assertions about any part of a Envelope:

```
{
    Subject [
        note: "A note about the subject."
        Predicate [
            note: "A note about the predicate."
        ] : Object [
            note: "A note about the object."
        ]
    ]
} [
    note: "A note about the Envelope as a whole."
]
```

Even leaf objects like strings and numbers can be transformed into Envelopes with their own assertions:

```
{
    Subject [
        note: {
            "A note about the subject." [
                lang: "en"
            ]
        }
        Predicate [
            note: {
                "A note about the predicate." [
                    lang: "en"
                ]
            }
        ] : Object [
            note: {
                "A note about the object." [
                    lang: "en"
                ]
            }
        ]
    ]
} [
    note: {
        "A note about the Envelope as a whole." [
            lang: "en"
        ]
    }
]
```

Thus, the `Envelope` type provides a flexible foundation for constructing solutions for various applications. Here are some high-level schematics of such applications in Envelope Notation. See the [EXAMPLES](6-EXAMPLES.md) chapter for more detail.

## Examples

---

## A container containing plaintext.

```
"Hello."
```

---

## A container containing signed plaintext.

This is the `.leaf` string with a single `Assertion` whose predicate is a well-known integer with a CBOR tag meaning `predicate`, while the object is a `Signature`.

```
"Hello." [
    verifiedBy: Signature
]
```

---

## A container containing plaintext signed by several parties.

Although you cannot have duplicate assertions every signature is unique, hence these are two *different* assertions.

```
"Hello." [
    verifiedBy: Signature
    verifiedBy: Signature
]
```

---

## A container containing a symmetrically encrypted message.

The subject is just an `EncryptedMessage`. Because this `EncryptedMessage` is the `subject` of an `Envelope`, we do know that its plaintext MUST be CBOR. This CBOR plaintext may be a leaf or another `Envelope` with more layers of assertions possibly  including signatures, but the receiver will have to decrypt it to find out.

```
EncryptedMessage
```

---

## A message that has been encrypted then signed.

The sender has first encrypted a message, then signed it. The signature can be verified before the actual message is decrypted because an encrypted `subject` carries the hash of the plaintext with it, and it is this hash that is used with the signature for verification.

```
EncryptedMessage [
    verifiedBy: Signature
]
```

---

## A message that can only be opened by specific receivers.

An ephemeral "content key" has been used to encrypt the message and the content key itself has been encrypted to one or more receipients' public keys. Therefore, only the intended recipients can decrypt and read the message, without the sender and receivers having to exchange a secret symmetric key first.

```
EncryptedMessage [
    hasRecipient: SealedMessage
    hasRecipient: SealedMessage
]
```

---

## A signed container that can only be opened by specific receivers.

As before, the signature can be outside the `subject` message, as below, or inside it, requiring decryption before verification.

```
EncryptedMessage [
    verifiedBy: Signature
    hasRecipient: SealedMessage
    hasRecipient: SealedMessage
]
```

---

## Several Envelopes containing a message split into several SSKR shares.

A message has been split into a three shares using SSKR and distributed to three trustees. Two of these shares must be recovered to reconstruct the original message.

```
EncryptedMessage [
    sskrShare: SSKRShare
]

EncryptedMessage [
    sskrShare: SSKRShare
]

EncryptedMessage [
    sskrShare: SSKRShare
]
```

---

## Complex Metadata

A specific digital object is identified and several layers of metadata are attributed to it. In this example some predicates are specified as strings (indicated by quotes) while other predicates use tagged well-known integers (no quotes).

This structure uses the `dereferenceVia` predicate to indicate that the full book in EPUB format may be retrieved using ExampleStore, and that its hash will match the hash provided, while more information about the author may be retrieved from the Library of Congress, and this information may change over time.

```
Digest(886d35d99ded5e20c61868e57af2f112700b73f1778d48284b0e078503d00ac1) [
    "format": "EPUB"
    "work": SCID(7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80) [
        "author": SCID(9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8) [
            dereferenceVia: "LibraryOfCongress"
            hasName: "Ayn Rand"
        ]
        "isbn": "9780451191144"
        dereferenceVia: "LibraryOfCongress"
        hasName: "Atlas Shrugged" [
            language: "en"
        ]
        hasName: "La rebelión de Atlas" [
            language: "es"
        ]
        isA: "novel"
    ]
    dereferenceVia: "ExampleStore"
]
```

---

## Verifiable Credential

A government wishes to issue a verifiable credential for permanent residency to an individual using a Self-Certifying Identifier (SCID) provided by that person.

```
{
    SCID(174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8) [
        "dateIssued": 2022-04-27
        holder: SCID(78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc) [
            "birthCountry": "bs" [
                note: "The Bahamas"
            ]
            "birthDate": 1974-02-18
            "familyName": "SMITH"
            "givenName": "JOHN"
            "image": Digest(4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54) [
                dereferenceVia: "https://exampleledger.com/digest/4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54"
                note: "This is an image of John Smith."
            ]
            "lprCategory": "C09"
            "lprNumber": "999-999-999"
            "residentSince": 2018-01-07
            "sex": "MALE"
            isA: "Permanent Resident"
            isA: "Person"
        ]
        isA: "credential"
        issuer: SCID(04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8) [
            dereferenceVia: URI(https://exampleledger.com/scid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
            note: "Issued by the State of Example"
        ]
        note: "The State of Example recognizes JOHN SMITH as a Permanent Resident."
    ]
} [
    verifiedBy: Signature [
        note: "Made by the State of Example."
    ]
]
```

---

## Redaction

The holder of a credential can then selectively reveal any of the micro-claims in this document. For instance, the holder could reveal just their name, their photo, and the issuer's signature, thereby proving that the issuer did indeed certify those facts.

Redaction is performed by building a set of `Digest`s that will be revealed. All digests not present in the reveal-set will be replaced with redaction markers containing only the hash of what has been redacted, thus preserving the hash tree including revealed signatures. If a higher-level object is redacted, then everything it contains will also be redacted, so if a deeper object is to be revealed, all of its parent objects up to the level of the verifying signature also need to be revealed, even though not everything *about* the parent objects must be revealed.

```
{
    SCID(174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8) [
        REDACTED: REDACTED
        REDACTED: REDACTED
        holder: SCID(78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc) [
            "familyName": "SMITH"
            "givenName": "JOHN"
            "image": Digest(4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54) [
                dereferenceVia: "https://exampleledger.com/digest/4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54"
                note: "This is an image of John Smith."
            ]
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
        ]
        isA: "credential"
        issuer: SCID(04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8) [
            dereferenceVia: URI(https://exampleledger.com/scid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
            note: "Issued by the State of Example"
        ]
    ]
} [
    verifiedBy: Signature [
        note: "Made by the State of Example."
    ]
]
```

## Envelope Notation vs. CBOR Diagnostic Notation

Envelope Notation compactly describes the potentially complex semantic structure of a `Envelope` in a friendly, human-readable format. For comparison, below is the same structure from the Credential example in CBOR diagnostic notation. The tags this CBOR structure uses are:

|CBOR Tag|Type|
|---|---|
|1|`Date`|
|32|`URI`|
|49|`Envelope`|
|56|`Digest`|
|58|`SCID`|
|59|`Predicate`|
|60|`.leaf`|
|61|`Signature`|

Integers below tagged 59 are well-known predicates:

|Integer|Predicate|
|---|---|
|2|`isA`|
|3|`verifiedBy`|
|4|`note`|
|9|`dereferenceVia`|
|13|`issuer`|
|14|`holder`|

```
49(
   [
      49(
         [
            60(
               58(
                  h'174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8'
               )
            ),
            [
               49(
                  60(
                     59(4)
                  )
               ),
               49(
                  60(
                     "The State of Example recognizes JOHN SMITH as a Permanent Resident."
                  )
               )
            ],
            [
               49(
                  60(
                     59(14)
                  )
               ),
               49(
                  [
                     60(
                        58(
                           h'78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc'
                        )
                     ),
                     [
                        49(
                           60("givenName")
                        ),
                        49(
                           60("JOHN")
                        )
                     ],
                     [
                        49(
                           60(
                              59(2)
                           )
                        ),
                        49(
                           60("Permanent Resident")
                        )
                     ],
                     [
                        49(
                           60("residentSince")
                        ),
                        49(
                           60(
                              1(2018-01-07T00:00:00Z)
                           )
                        )
                     ],
                     [
                        49(
                           60(
                              59(2)
                           )
                        ),
                        49(
                           60("Person")
                        )
                     ],
                     [
                        49(
                           60("familyName")
                        ),
                        49(
                           60("SMITH")
                        )
                     ],
                     [
                        49(
                           60("image")
                        ),
                        49(
                           [
                              60(
                                 56(
                                    h'4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54'
                                 )
                              ),
                              [
                                 49(
                                    60(
                                       59(9)
                                    )
                                 ),
                                 49(
                                    60(
                                       "https://exampleledger.com/digest/4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54"
                                    )
                                 )
                              ],
                              [
                                 49(
                                    60(
                                       59(4)
                                    )
                                 ),
                                 49(
                                    60(
                                       "This is an image of John Smith."
                                    )
                                 )
                              ]
                           ]
                        )
                     ],
                     [
                        49(
                           60("sex")
                        ),
                        49(
                           60("MALE")
                        )
                     ],
                     [
                        49(
                           60("birthDate")
                        ),
                        49(
                           60(
                              1(1974-02-18T00:00:00Z)
                           )
                        )
                     ],
                     [
                        49(
                           60("lprNumber")
                        ),
                        49(
                           60("999-999-999")
                        )
                     ],
                     [
                        49(
                           60("birthCountry")
                        ),
                        49(
                           [
                              60("bs"),
                              [
                                 49(
                                    60(
                                       59(4)
                                    )
                                 ),
                                 49(
                                    60("The Bahamas")
                                 )
                              ]
                           ]
                        )
                     ],
                     [
                        49(
                           60("lprCategory")
                        ),
                        49(
                           60("C09")
                        )
                     ]
                  ]
               )
            ],
            [
               49(
                  60(
                     59(13)
                  )
               ),
               49(
                  [
                     60(
                        58(
                           h'04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8'
                        )
                     ),
                     [
                        49(
                           60(
                              59(4)
                           )
                        ),
                        49(
                           60(
                              "Issued by the State of Example"
                           )
                        )
                     ],
                     [
                        49(
                           60(
                              59(9)
                           )
                        ),
                        49(
                           60(
                              32(
                                 "https://exampleledger.com/scid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8"
                              )
                           )
                        )
                     ]
                  ]
               )
            ],
            [
               49(
                  60(
                     59(2)
                  )
               ),
               49(
                  60("credential")
               )
            ],
            [
               49(
                  60("dateIssued")
               ),
               49(
                  60(
                     1(2022-04-27T00:00:00Z)
                  )
               )
            ]
         ]
      ),
      [
         49(
            60(
               59(3)
            )
         ),
         49(
            [
               60(
                  61(
                     h'0f8a3cfc2139ded0fa4dd4ea80bad8b5c3f18bf3523e0063793056910980e2b3d8b51ee2fcc4ca17aeb559741deb954a6b0ecb089ff8d56b4d46a7c84656d6a1'
                  )
               ),
               [
                  49(
                     60(
                        59(4)
                     )
                  ),
                  49(
                     60(
                        "Made by the State of Example."
                     )
                  )
               ]
            ]
         )
      ]
   ]
)
```
