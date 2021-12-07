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
