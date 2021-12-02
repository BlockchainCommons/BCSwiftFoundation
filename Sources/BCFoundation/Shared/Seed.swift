//
//  Seed.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/15/21.
//

import Foundation
@_exported import URKit

public enum SeedError: Swift.Error {
    case unexpectedURType
    case unexpectedTag
    case invalidCBOR
    case invalidFormat
}

public protocol SeedProtocol: IdentityDigestable {
    var data: Data { get }
    var name: String { get set }
    var note: String { get set }
    var creationDate: Date? { get set }
    
    init?(data: Data, name: String, note: String, creationDate: Date?)
    init?(data: Data)
    /// Copy constructor
    init(_ seed: SeedProtocol)
    init()
}

public struct Seed: SeedProtocol {
    public let data: Data
    public var name: String
    public var note: String
    public var creationDate: Date?
    
    public init?(data: Data, name: String = "", note: String = "", creationDate: Date? = nil) {
        guard data.count <= 32 else {
            return nil
        }
        self.data = data
        self.name = name
        self.note = note
        self.creationDate = creationDate
    }
    
    public init?(data: Data) {
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
    public func cbor(nameLimit: Int = .max, noteLimit: Int = .max) -> CBOR {
        var a: [OrderedMapEntry] = [
            .init(key: 1, value: CBOR.byteString(data.bytes))
        ]
        
        if let creationDate = creationDate {
            a.append(.init(key: 2, value: CBOR.date(creationDate)))
        }

        if !name.isEmpty {
            a.append(.init(key: 3, value: CBOR.utf8String(name.prefix(count: nameLimit))))
        }

        if !note.isEmpty {
            a.append(.init(key: 4, value: CBOR.utf8String(note.prefix(count: noteLimit))))
        }

        return CBOR.orderedMap(a)
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(.seed, cbor())
    }

    public var ur: UR {
        try! UR(type: "crypto-seed", cbor: cbor())
    }
    
    public var sizeLimitedUR: UR {
        try! UR(type: "crypto-seed", cbor: cbor(nameLimit: 100, noteLimit: 500))
    }
}

extension SeedProtocol {
    public init(ur: UR) throws {
        guard ur.type == "crypto-seed" else {
            throw SeedError.unexpectedURType
        }
        try self.init(cborData: ur.cbor)
    }

    public init(urString: String) throws {
        let ur = try URDecoder.decode(urString)
        try self.init(ur: ur)
    }

    public init(cborData: Data) throws {
        guard let cbor = try CBOR.decode(cborData.bytes) else {
            throw SeedError.invalidCBOR
        }
        try self.init(cbor: cbor)
    }

    public init(cbor: CBOR) throws {
        guard case let CBOR.map(pairs) = cbor else {
            // CBOR doesn't contain a map.
            throw SeedError.invalidFormat
        }
        guard
            let dataItem = pairs[1],
            case let CBOR.byteString(bytes) = dataItem,
            !bytes.isEmpty
        else {
            // CBOR doesn't contain data field.
            throw SeedError.invalidFormat
        }
        let data = Data(bytes)
        
        let creationDate: Date?
        if let dateItem = pairs[2] {
            guard case let CBOR.date(d) = dateItem else {
                // CreationDate field doesn't contain a date.
                throw SeedError.invalidFormat
            }
            creationDate = d
        } else {
            creationDate = nil
        }

        let name: String
        if let nameItem = pairs[3] {
            guard case let CBOR.utf8String(s) = nameItem else {
                // Name field doesn't contain string.
                throw SeedError.invalidFormat
            }
            name = s
        } else {
            name = "Untitled"
        }

        let note: String
        if let noteItem = pairs[4] {
            guard case let CBOR.utf8String(s) = noteItem else {
                // Note field doesn't contain string.
                throw SeedError.invalidFormat
            }
            note = s
        } else {
            note = ""
        }
        self.init(data: data, name: name, note: note, creationDate: creationDate)!
    }

    public init(taggedCBOR: Data) throws {
        guard let cbor = try CBOR.decode(taggedCBOR.bytes) else {
            throw SeedError.invalidCBOR
        }
        guard case let CBOR.tagged(tag, content) = cbor, tag == .seed else {
            throw SeedError.unexpectedTag
        }
        try self.init(cbor: content)
    }
}

extension SeedProtocol {
    public var identityDigestSource: Data {
        data
    }
}
