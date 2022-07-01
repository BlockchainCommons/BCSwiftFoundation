//
//  TransactionRequest.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import URKit

public enum TransactionRequestError: Swift.Error {
    case unknownRequestType
}

public struct TransactionRequest {
    public let id: UUID
    public let body: Body
    public let note: String?

    public init(id: UUID = UUID(), body: Body, note: String? = nil) {
        self.id = id
        self.body = body
        self.note = note
    }

    public enum Body {
        case seed(SeedRequestBody)
        case key(KeyRequestBody)
        case psbtSignature(PSBTSignatureRequestBody)
        case outputDescriptor(OutputDescriptorRequestBody)
    }
    
    public func cbor(noteLimit: Int = .max) -> CBOR {
        var a: OrderedMap = [1: id.taggedCBOR]
        
        switch body {
        case .seed(let body):
            a.append(2, body.taggedCBOR)
        case .key(let body):
            a.append(2, body.taggedCBOR)
        case .psbtSignature(let body):
            a.append(2, body.taggedCBOR)
        case .outputDescriptor(let body):
            a.append(2, body.taggedCBOR)
        }
        
        if let note = note {
            a.append(3, CBOR.utf8String(note.prefix(count: noteLimit)))
        }
        
        return CBOR.orderedMap(a)
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.transactionRequest.tag, cbor())
    }
    
    public init(ur: UR) throws {
        switch ur.type {
        case URType.transactionRequest.type:
            try self.init(cborData: ur.cbor)
        case URType.psbt.type:
            try self.init(cborData: ur.cbor, isRawPSBT: true)
        default:
            throw URError.unexpectedType
        }
    }
    
    public init(cborData: Data, isRawPSBT: Bool = false) throws {
        let cbor = try CBOR(cborData)
        if isRawPSBT {
            let psbt = try PSBT(untaggedCBOR: cbor)
            let body = TransactionRequest.Body.psbtSignature(PSBTSignatureRequestBody(psbt: psbt, isRawPSBT: true))
            self.init(id: UUID(), body: body, note: nil)
        } else {
            try self.init(untaggedCBOR: cbor)
        }
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.map(pairs) = untaggedCBOR else {
            // CBOR doesn't contain a map.
            throw CBORError.invalidFormat
        }
        
        guard let idItem = pairs[1] else {
            // CBOR doesn't contain a transaction ID.
            throw CBORError.invalidFormat
        }
        let id = try UUID(taggedCBOR: idItem)
        
        guard let bodyItem = pairs[2] else {
            // CBOR doesn't contain a body.
            throw CBORError.invalidFormat
        }
        
        let body: Body
        
        if let seedRequestBody = try SeedRequestBody(taggedCBOR: bodyItem) {
            body = Body.seed(seedRequestBody)
        } else if let keyRequestBody = try KeyRequestBody(taggedCBOR: bodyItem) {
            body = Body.key(keyRequestBody)
        } else if let psbtSignatureRequestBody = try PSBTSignatureRequestBody(taggedCBOR: bodyItem) {
            body = Body.psbtSignature(psbtSignatureRequestBody)
        } else if let outputDescriptorRequestBody = try OutputDescriptorRequestBody(taggedCBOR: bodyItem) {
            body = Body.outputDescriptor(outputDescriptorRequestBody)
        } else {
            throw TransactionRequestError.unknownRequestType
        }
        
        let note: String?
        
        if let noteItem = pairs[3] {
            guard case let CBOR.utf8String(d) = noteItem else {
                // note is not a string
                throw CBORError.invalidFormat
            }
            note = d
        } else {
            note = nil
        }
        
        self.init(id: id, body: body, note: note)
    }

    public var ur: UR {
        try! UR(type: URType.transactionRequest.type, cbor: cbor())
    }
    
    public func sizeLimitedUR(noteLimit: Int = 500) -> UR {
        try! UR(type: URType.transactionRequest.type, cbor: cbor(noteLimit: noteLimit))
    }
}
