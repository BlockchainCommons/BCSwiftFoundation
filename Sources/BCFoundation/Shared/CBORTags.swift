//
//  CBORTags.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import URKit

/// https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md
extension CBOR.Tag {
    public static let seed = CBOR.Tag(300)
    public static let hdKey = CBOR.Tag(303)
    public static let derivationPath = CBOR.Tag(304)
    public static let useInfo = CBOR.Tag(305)
    public static let ecKey = CBOR.Tag(306)
    public static let address = CBOR.Tag(307)
    public static let output = CBOR.Tag(308)
    public static let sskrShare = CBOR.Tag(309)
    public static let psbt = CBOR.Tag(310)
    public static let transactionRequest = CBOR.Tag(312)
    public static let transactionResponse = CBOR.Tag(313)
}

/// Tags for subtypes specific to crypto-output
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
}

/// Tags for subtypes specific to crypto-request
extension CBOR.Tag {
    public static let seedRequestBody = CBOR.Tag(500)
    public static let keyRequestBody = CBOR.Tag(501)
    public static let psbtSignatureRequestBody = CBOR.Tag(502)
}
