//
//  TransactionRequest.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import URKit

public struct TransactionRequest {
    public let id: UUID
    public let body: Body
    public let note: String?

    public init(id: UUID, body: Body, note: String?) {
        self.id = id
        self.body = body
        self.note = note
    }

    public enum Body {
        case seed(SeedRequestBody)
        case key(KeyRequestBody)
        case psbtSignature(PSBTSignatureRequestBody)
    }
    
    public func cbor(noteLimit: Int = .max) -> CBOR {
        var a: [OrderedMapEntry] = []
        
        a.append(.init(key: 1, value: id.taggedCBOR))
        
        switch body {
        case .seed(let body):
            a.append(.init(key: 2, value: body.taggedCBOR))
        case .key(let body):
            a.append(.init(key: 2, value: body.taggedCBOR))
        case .psbtSignature(let body):
            a.append(.init(key: 2, value: body.taggedCBOR))
        }
        
        if let note = note {
            a.append(.init(key: 3, value: CBOR.utf8String(note.prefix(count: noteLimit))))
        }
        
        return CBOR.orderedMap(a)
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(.transactionRequest, cbor())
    }
    
    public init(ur: UR) throws {
        switch ur.type {
        case "crypto-request":
            try self.init(cborData: ur.cbor)
        case "crypto-psbt":
            try self.init(cborData: ur.cbor, isRawPSBT: true)
        default:
            throw Error.invalidURType
        }
    }

    public init(id: UUID = UUID(), body: TransactionRequest.Body, description: String? = nil) {
        self.id = id
        self.body = body
        self.note = description
    }
    
    public init(cborData: Data, isRawPSBT: Bool = false) throws {
        guard let cbor = try CBOR.decode(cborData.bytes) else {
            throw Error.invalidFormat
        }
        if isRawPSBT {
            let psbt = try PSBT(cbor: cbor)
            let body = TransactionRequest.Body.psbtSignature(PSBTSignatureRequestBody(psbt: psbt, isRawPSBT: true))
            self.init(id: UUID(), body: body, description: nil)
        } else {
            try self.init(cbor: cbor)
        }
    }
    
    public init(cbor: CBOR) throws {
        guard case let CBOR.map(pairs) = cbor else {
            // CBOR doesn't contain a map.
            throw Error.invalidFormat
        }
        
        guard let idItem = pairs[1] else {
            // CBOR doesn't contain a transaction ID.
            throw Error.invalidFormat
        }
        let id = try UUID(taggedCBOR: idItem)
        
        guard let bodyItem = pairs[2] else {
            // CBOR doesn't contain a body.
            throw Error.invalidFormat
        }
        
        let body: Body
        
        if let seedRequestBody = try SeedRequestBody(taggedCBOR: bodyItem) {
            body = Body.seed(seedRequestBody)
        } else if let keyRequestBody = try KeyRequestBody(taggedCBOR: bodyItem) {
            body = Body.key(keyRequestBody)
        } else if let psbtSignatureRequestBody = try PSBTSignatureRequestBody(taggedCBOR: bodyItem) {
            body = Body.psbtSignature(psbtSignatureRequestBody)
        } else {
            throw Error.unknownRequestType
        }
        
        let description: String?
        
        if let descriptionItem = pairs[3] {
            guard case let CBOR.utf8String(d) = descriptionItem else {
                // description is not a string
                throw Error.invalidFormat
            }
            description = d
        } else {
            description = nil
        }
        
        self.init(id: id, body: body, description: description)
    }

    public var ur: UR {
        try! UR(type: "crypto-request", cbor: cbor())
    }
    
    public var sizeLimitedUR: UR {
        try! UR(type: "crypto-request", cbor: cbor(noteLimit: 500))
    }
    
    public enum Error: Swift.Error {
        case invalidURType
        case invalidFormat
        case unknownRequestType
    }
}
