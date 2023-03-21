//
//  Seed.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/15/21.
//

import Foundation
import WolfBase
import URKit
import SecureComponents

public protocol SeedProtocol: IdentityDigestable, Equatable, PrivateKeysDataProvider, URCodable {
    var data: Data { get }
    var name: String { get set }
    var note: String { get set }
    var creationDate: Date? { get set }
    
    init?(data: DataProvider, name: String, note: String, creationDate: Date?)
    init?(data: DataProvider)
    /// Copy constructor
    init(_ seed: any SeedProtocol)
    init()
}

public extension SeedProtocol/*: PrivateKeysDataProvider*/ {
    var privateKeysData: Data {
        data
    }
}

public let minSeedSize = 16

public struct Seed: SeedProtocol {
    public static var cborTag: Tag = .seed
    
    public let data: Data
    public var name: String
    public var note: String
    public var creationDate: Date?
    
    public init?(data: DataProvider, name: String = "", note: String = "", creationDate: Date? = nil) {
        let data = data.providedData
        guard data.count >= minSeedSize else {
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
    public init(_ seed: any SeedProtocol) {
        self.init(data: seed.data, name: seed.name, note: seed.note, creationDate: seed.creationDate)!
    }

    public init() {
        self.init(data: SecureRandomNumberGenerator.shared.data(count: minSeedSize))!
    }
}

public extension SeedProtocol {
    init?(hex: String) {
        guard let data = hex.hexData else {
            return nil
        }
        self.init(data: data)
    }

    var hex: String {
        data.hex
    }

    init(count: Int) {
        self.init(data: SecureRandomNumberGenerator.shared.data(count: count))!
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
    public var untaggedCBOR: CBOR {
        cbor().0
    }

    public func cbor(nameLimit: Int = .max, noteLimit: Int = .max) -> (CBOR, Bool) {
        var a: Map = [1: data]
        var didLimit = false

        if let creationDate = creationDate {
            a[2] = creationDate.cbor
        }

        if !name.isEmpty {
            let limitedName = name.prefix(count: nameLimit)
            didLimit = didLimit || limitedName.count < name.count
            a[3] = limitedName.cbor
        }

        if !note.isEmpty {
            let limitedNote = note.prefix(count: noteLimit)
            didLimit = didLimit || limitedNote.count < note.count
            a[4] = limitedNote.cbor
        }

        return (CBOR.map(a), didLimit)
    }
    
    public func sizeLimitedUR(nameLimit: Int = 100, noteLimit: Int = 500) -> (UR, Bool) {
        let (c, didLimit) = cbor(nameLimit: nameLimit, noteLimit: noteLimit)
        return try! (UR(type: Tag.seed.name!, untaggedCBOR: c), didLimit)
    }
}

extension SeedProtocol {
    public init(untaggedCBOR: CBOR) throws {
        guard case CBOR.map(let map) = untaggedCBOR else {
            // CBOR doesn't contain a map.
            throw CBORError.invalidFormat
        }
        
        guard
            let dataItem = map[1],
            case let CBOR.bytes(bytes) = dataItem,
            !bytes.isEmpty
        else {
            // CBOR doesn't contain data field.
            throw CBORError.invalidFormat
        }
        let data = bytes.data
        
        let creationDate: Date?
        if let dateItem = map[2] {
            
            creationDate = try Date(cbor: dateItem)
        } else {
            creationDate = nil
        }

        let name: String
        if let nameItem = map[3] {
            guard case let CBOR.text(s) = nameItem else {
                // Name field doesn't contain string.
                throw CBORError.invalidFormat
            }
            name = s
        } else {
            name = ""
        }

        let note: String
        if let noteItem = map[4] {
            guard case let CBOR.text(s) = noteItem else {
                // Note field doesn't contain string.
                throw CBORError.invalidFormat
            }
            note = s
        } else {
            note = ""
        }
        self.init(data: data, name: name, note: note, creationDate: creationDate)!
    }
}

extension SeedProtocol {
    public var identityDigestSource: Data {
        data
    }
}

//extension Seed: CBOREncodable {
//    public var cbor: CBOR {
//        taggedCBOR
//    }
//}
//
//extension Seed: CBORDecodable {
//    public static func cborDecode(_ cbor: CBOR) throws -> Seed {
//        try Seed(taggedCBOR: cbor)
//    }
//}

extension Seed: TransactionResponseBody {
    public var envelope: Envelope { Envelope(self) }
}
