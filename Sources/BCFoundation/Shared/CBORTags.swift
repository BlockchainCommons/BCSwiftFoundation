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
    public static let profile = URType(type: "crypto-profile", tag: 50)
    public static let peer = URType(type: "crypto-peer", tag: 51)
    public static let sealedMessage = URType(type: "crypto-sealed", tag: 55)
    public static let digest = URType(type: "crypto-digest", tag: 700)
    public static let symmetricKey = URType(type: "crypto-key", tag: 708)
}

/// Tags for subtypes specific to AccountBundle (crypto-output)
extension CBOR.Tag {
    public static let outputScriptHash = CBOR.Tag(400)
    public static let outputWitnessScriptHash = CBOR.Tag(401)
    public static let outputPublicKey = CBOR.Tag(402)
    public static let outputPublicKeyHash = CBOR.Tag(403)
    public static let outputWitnessPublicKeyHash = CBOR.Tag(404)
    public static let outputCombo = CBOR.Tag(405)
    public static let outputMultisig = CBOR.Tag(406)
    public static let outputSortedMultisig = CBOR.Tag(407)
    public static let outputRawScript = CBOR.Tag(408)
    public static let outputTaproot = CBOR.Tag(409)
    public static let outputCosigner = CBOR.Tag(410)
}

/// Tags for subtypes specific to crypto-request
extension CBOR.Tag {
    public static let seedRequestBody = CBOR.Tag(500)
    public static let keyRequestBody = CBOR.Tag(501)
    public static let psbtSignatureRequestBody = CBOR.Tag(502)
}

extension CBOR.Tag {
    public static let seedDigest = CBOR.Tag(600)
}

extension CBOR.Tag {
    public static let password = CBOR.Tag(701)
    public static let permit = CBOR.Tag(702)
    public static let agreementPrivateKey = CBOR.Tag(703)
    public static let agreementPublicKey = CBOR.Tag(704)
    public static let signingPrivateKey = CBOR.Tag(705)
    public static let signingPublicKey = CBOR.Tag(706)
    public static let signature = CBOR.Tag(707)
}
