//
//  Seed.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/15/21.
//

import Foundation
import WolfBase
import URKit

public protocol SeedProtocol: IdentityDigestable {
    var data: Data { get }
    var name: String { get set }
    var note: String { get set }
    var creationDate: Date? { get set }
    
    init?(data: DataProvider, name: String, note: String, creationDate: Date?)
    init?(data: DataProvider)
    /// Copy constructor
    init(_ seed: SeedProtocol)
    init()
}

public struct Seed: SeedProtocol {
    public let data: Data
    public var name: String
    public var note: String
    public var creationDate: Date?
    
    public init?(data: DataProvider, name: String = "", note: String = "", creationDate: Date? = nil) {
        let data = data.providedData
        guard data.count <= 32 else {
            return nil
        }
        self.data = data
        self.name = name
        self.note = note
        self.creationDate = creationDate
    }
    
    public init?(data: DataProvider) {
        self.init(data: data, name: "", note: "", creationDate: nil)
    }

    /// Copy constructor
    public init(_ seed: SeedProtocol) {
        self.init(data: seed.data, name: seed.name, note: seed.note, creationDate: seed.creationDate)!
    }

    public init() {
        self.init(data: SecureRandomNumberGenerator.shared.data(count: 16))!
    }
}

extension SeedProtocol {
    public init?(hex: String) {
        guard let data = hex.hexData else {
            return nil
        }
        self.init(data: data)
    }

    public var hex: String {
        data.hex
    }
}

extension SeedProtocol {
    public var bip39: BIP39 {
        BIP39(data: data)!
    }
    
    public init(bip39: BIP39) {
        self.init(data: bip39.data)!
    }
    
    public init?(mnemonic: String) {
        guard let bip39 = BIP39(mnemonic: mnemonic) else {
            return nil
        }
        self.init(bip39: bip39)
    }
}

extension SeedProtocol {
    public func cbor(nameLimit: Int = .max, noteLimit: Int = .max) -> (CBOR, Bool) {
        var a: OrderedMap = [1: .data(data)]
        var didLimit = false

        if let creationDate = creationDate {
            a.append(2, .date(creationDate))
        }

        if !name.isEmpty {
            let limitedName = name.prefix(count: nameLimit)
            didLimit = didLimit || limitedName.count < name.count
            a.append(3, .utf8String(limitedName))
        }

        if !note.isEmpty {
            let limitedNote = note.prefix(count: noteLimit)
            didLimit = didLimit || limitedNote.count < note.count
            a.append(4, .utf8String(limitedNote))
        }

        return (CBOR.orderedMap(a), didLimit)
    }

    public var taggedCBOR: CBOR {
        let (c, _) = cbor()
        return CBOR.tagged(URType.seed.tag, c)
    }

    public var ur: UR {
        let (c, _) = cbor()
        return try! UR(type: URType.seed.type, cbor: c)
    }
    
    public func sizeLimitedUR(nameLimit: Int = 100, noteLimit: Int = 500) -> (UR, Bool) {
        let (c, didLimit) = cbor(nameLimit: nameLimit, noteLimit: noteLimit)
        return try! (UR(type: URType.seed.type, cbor: c), didLimit)
    }
}

extension SeedProtocol {
    public init(ur: UR) throws {
        guard ur.type == URType.seed.type else {
            throw URError.unexpectedType
        }
        try self.init(cborData: ur.cbor)
    }

    public init(urString: String) throws {
        let ur = try URDecoder.decode(urString)
        try self.init(ur: ur)
    }

    public init(cborData: Data) throws {
        let cbor = try CBOR(cborData)
        try self.init(untaggedCBOR: cbor)
    }

    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.map(pairs) = untaggedCBOR else {
            // CBOR doesn't contain a map.
            throw CBORError.invalidFormat
        }
        guard
            let dataItem = pairs[1],
            case let CBOR.data(bytes) = dataItem,
            !bytes.isEmpty
        else {
            // CBOR doesn't contain data field.
            throw CBORError.invalidFormat
        }
        let data = bytes.data
        
        let creationDate: Date?
        if let dateItem = pairs[2] {
            guard case let CBOR.date(d) = dateItem else {
                // CreationDate field doesn't contain a date.
                throw CBORError.invalidFormat
            }
            creationDate = d
        } else {
            creationDate = nil
        }

        let name: String
        if let nameItem = pairs[3] {
            guard case let CBOR.utf8String(s) = nameItem else {
                // Name field doesn't contain string.
                throw CBORError.invalidFormat
            }
            name = s
        } else {
            name = ""
        }

        let note: String
        if let noteItem = pairs[4] {
            guard case let CBOR.utf8String(s) = noteItem else {
                // Note field doesn't contain string.
                throw CBORError.invalidFormat
            }
            note = s
        } else {
            note = ""
        }
        self.init(data: data, name: name, note: note, creationDate: creationDate)!
    }

    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(tag, content) = taggedCBOR, tag == URType.seed.tag else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: content)
    }

    public init(taggedCBOR: Data) throws {
        try self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension SeedProtocol {
    public var identityDigestSource: Data {
        data
    }
}

extension Seed: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension Seed: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Seed {
        try Seed(taggedCBOR: cbor)
    }
}

