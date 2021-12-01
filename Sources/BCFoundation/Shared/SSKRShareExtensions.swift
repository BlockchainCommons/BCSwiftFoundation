//
//  File.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import SSKR
@_exported import URKit

extension SSKRShare: Hashable {
    public var identifier: UInt16 {
        (UInt16(data[0]) << 8) | UInt16(data[1])
    }
    
    public var identifierHex: String {
        Data(data[0...1]).hex
    }

    public var groupThreshold: Int {
        Int(data[2] >> 4) + 1
    }
    
    public var groupCount: Int {
        Int(data[2] & 0xf) + 1
    }
    
    public var groupIndex: Int {
        Int(data[3]) >> 4
    }
    
    public var memberThreshold: Int {
        Int(data[3] & 0xf) + 1
    }
    
    public var memberIndex: Int {
        Int(data[4] & 0xf)
    }
    
    public static func ==(lhs: SSKRShare, rhs: SSKRShare) -> Bool {
        lhs.data == rhs.data
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(data)
    }
    
    public init?(bytewords: String) throws {
        guard let share = try? Bytewords.decode(bytewords) else {
            return nil
        }
        self = try SSKRShare(data: share.decodeCBOR(isTagged: true).bytes)
    }
    
    public init?(urString: String) throws {
        guard let ur = try? URDecoder.decode(urString) else {
            return nil
        }
        try self.init(ur: ur)
    }
    
    public init(ur: UR) throws {
        guard ur.type == "crypto-sskr" else {
            throw SSKRError.invalidURType
        }

        self = try SSKRShare(data: ur.cbor.decodeCBOR(isTagged: false).bytes)
    }

    public var ur: UR {
        let cbor = CBOR.encode(Data(data))
        return try! UR(type: "crypto-sskr", cbor: cbor)
    }
    
    public var urString: String {
        return UREncoder.encode(ur)
    }

    public var bytewords: String {
        let cbor = CBOR.encodeTagged(tag: .sskrShare, value: Data(data))
        return Bytewords.encode(Data(cbor), style: .standard)
    }
}

extension SSKRShare: CustomStringConvertible {
    public var description: String {
        "SSKRShare(\(identifierHex) \(groupIndex + 1)-\(memberIndex + 1))"
    }
}

extension Data {
    fileprivate func decodeCBOR(isTagged: Bool) throws -> Data {
        guard let cbor = try CBOR.decode(self.bytes) else {
            throw SSKRError.invalidCBOR
        }
        let content: CBOR
        if isTagged {
            guard case let CBOR.tagged(tag, _content) = cbor, tag == .sskrShare else {
                throw SSKRError.invalidTag
            }
            content = _content
        } else {
            content = cbor
        }
        guard case let CBOR.byteString(bytes) = content else {
            throw SSKRError.invalidFormat
        }
        return Data(bytes)
    }
}

public enum SSKRError: Error {
    case invalidURType
    case invalidCBOR
    case invalidTag
    case invalidFormat
}
