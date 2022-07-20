//
//  CBORTags.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import URKit

/// https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md

public struct URType {
    public let type: String
    public let tag: CBOR.Tag
    
    public init(type: String, tag: UInt64) {
        self.type = type
        self.tag = CBOR.Tag(tag, type)
    }
}

/// UR types and CBOR tags for objects that can be top-level.
extension URType {
    public static let seed = URType(type: "crypto-seed", tag: 300)
    public static let hdKey = URType(type: "crypto-hdkey", tag: 303)
    public static let derivationPath = URType(type: "crypto-keypath", tag: 304)
    public static let useInfo = URType(type: "crypto-coin-info", tag: 305)
    public static let ecKey = URType(type: "crypto-eckey", tag: 306)
    public static let address = URType(type: "crypto-address", tag: 307)
    public static let output = URType(type: "crypto-output", tag: 308)
    public static let sskrShare = URType(type: "crypto-sskr", tag: 309)
    public static let psbt = URType(type: "crypto-psbt", tag: 310)
    public static let account = URType(type: "crypto-account", tag: 311)
    public static let transactionRequest = URType(type: "crypto-request", tag: 312)
    public static let transactionResponse = URType(type: "crypto-response", tag: 313)

    public static let message = URType(type: "crypto-msg", tag: 48)
    public static let envelope = URType(type: "crypto-envelope", tag: 49)
    public static let privateKeyBase = URType(type: "crypto-prvkeys", tag: 50)
    public static let publicKeyBase = URType(type: "crypto-pubkeys", tag: 51)
    public static let sealedMessage = URType(type: "crypto-sealed", tag: 55)
    public static let digest = URType(type: "crypto-digest", tag: 56)
    public static let symmetricKey = URType(type: "crypto-key", tag: 57)
    public static let scid = URType(type: "crypto-scid", tag: 58)
}

/// Tags for subtypes specific to AccountBundle (crypto-output)
extension CBOR.Tag {
    public static let outputScriptHash = CBOR.Tag(400, "output-script-hash")
    public static let outputWitnessScriptHash = CBOR.Tag(401, "output-witness-script-hash")
    public static let outputPublicKey = CBOR.Tag(402, "output-public-key")
    public static let outputPublicKeyHash = CBOR.Tag(403, "output-public-key-hash")
    public static let outputWitnessPublicKeyHash = CBOR.Tag(404, "output-witness-public-key-hash")
    public static let outputCombo = CBOR.Tag(405, "output-combo")
    public static let outputMultisig = CBOR.Tag(406, "output-multisig")
    public static let outputSortedMultisig = CBOR.Tag(407, "output-sorted-multisig")
    public static let outputRawScript = CBOR.Tag(408, "output-raw-script")
    public static let outputTaproot = CBOR.Tag(409, "output-taproot")
    public static let outputCosigner = CBOR.Tag(410, "output-cosigner")
}

/// Tags for subtypes specific to crypto-request
extension CBOR.Tag {
    public static let seedRequestBody = CBOR.Tag(500, "seed-request-body")
    public static let keyRequestBody = CBOR.Tag(501, "key-request-body")
    public static let psbtSignatureRequestBody = CBOR.Tag(502, "psbt-signature-request-body")
    public static let outputDescriptorRequestBody = CBOR.Tag(503, "output-descriptor-request-body")
    public static let outputDescriptorResponseBody = CBOR.Tag(504, "output-descriptor-response-body")
}

extension CBOR.Tag {
    public static let seedDigest = CBOR.Tag(600, "seed-digest")
}

/// Tags for subtypes specific to Secure Components
extension CBOR.Tag {
    public static let predicate = CBOR.Tag(59, "predicate")
    public static let plaintext = CBOR.Tag(60, "plaintext")
    public static let signature = CBOR.Tag(61, "signature")
    public static let agreementPublicKey = CBOR.Tag(62, "agreement-public-key")
    
    public static let password = CBOR.Tag(700, "password")
    public static let agreementPrivateKey = CBOR.Tag(702, "agreement-private-key")
    public static let signingPrivateKey = CBOR.Tag(704, "signing-private-key")
    public static let signingPublicKey = CBOR.Tag(705, "signing-public-key")
    public static let nonce = CBOR.Tag(707, "nonce")
}
