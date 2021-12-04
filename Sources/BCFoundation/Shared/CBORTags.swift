//
//  CBORTags.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import URKit

extension CBOR.Tag {
    public static let seed = CBOR.Tag(300)
    public static let hdKey = CBOR.Tag(303)
    public static let derivationPath = CBOR.Tag(304)
    public static let useInfo = CBOR.Tag(305)
    public static let address = CBOR.Tag(307)
    public static let sskrShare = CBOR.Tag(309)
    public static let psbt = CBOR.Tag(310)
    public static let transactionRequest = CBOR.Tag(312)
    public static let transactionResponse = CBOR.Tag(313)
    
    public static let seedRequestBody = CBOR.Tag(500)
    public static let keyRequestBody = CBOR.Tag(501)
    public static let psbtSignatureRequestBody = CBOR.Tag(502)
}
