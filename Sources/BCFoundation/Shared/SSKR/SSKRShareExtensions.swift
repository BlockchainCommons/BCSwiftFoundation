//
//  SSKRShareExtensions.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import WolfBase
@_exported import SSKR
@_exported import URKit

public func SSKRGenerate(groupThreshold: Int, groups: [SSKRGroupDescriptor], secret: DataProvider, randomGenerator: ((Int) -> Data)? = nil) throws -> [[SSKRShare]] {
    let randomGenerator = randomGenerator ?? {
        SecureRandomNumberGenerator.shared.data(count: $0)
    }
    return try SSKRGenerate(groupThreshold: groupThreshold, groups: groups, secret: secret.providedData, randomGenerator: randomGenerator)
}

public func SSKRGenerate(groupThreshold: Int, groups: [(Int, Int)], secret: DataProvider, randomGenerator: ((Int) -> Data)? = nil) throws -> [[SSKRShare]] {
    let groups = groups.map { SSKRGroupDescriptor(threshold: UInt8($0.0), count: UInt8($0.1)) }
    return try SSKRGenerate(groupThreshold: groupThreshold, groups: groups, secret: secret.providedData, randomGenerator: randomGenerator)
}

extension SSKRShare {
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
}

extension SSKRShare: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(data)
    }
}

extension SSKRShare {
    public var untaggedCBOR: CBOR {
        CBOR.data(Data(data))
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.sskrShare.tag, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.data(data) = untaggedCBOR else {
            throw CBORError.invalidFormat
        }
        self = SSKRShare(data: data.bytes)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.sskrShare.tag, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension SSKRShare {
    public func bytewords(style: Bytewords.Style) -> String {
        return Bytewords.encode(taggedCBOR.cborEncode, style: style)
    }

    public init?(bytewords: String) throws {
        guard let share = try? Bytewords.decode(bytewords) else {
            return nil
        }
        self = try SSKRShare(taggedCBOR: CBOR(share))
    }
}

extension SSKRShare {
    public var ur: UR {
        return try! UR(type: URType.sskrShare.type, cbor: untaggedCBOR)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.sskrShare.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        self = try SSKRShare(untaggedCBOR: cbor)
    }
    
    public var urString: String {
        return UREncoder.encode(ur)
    }

    public init?(urString: String) throws {
        guard let ur = try? URDecoder.decode(urString) else {
            return nil
        }
        try self.init(ur: ur)
    }
}

extension SSKRShare: CustomStringConvertible {
    public var description: String {
        "SSKRShare(\(identifierHex) \(groupIndex + 1)-\(memberIndex + 1))"
    }
}

extension SSKRShare: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension SSKRShare: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> SSKRShare {
        try SSKRShare(taggedCBOR: cbor)
    }
}
