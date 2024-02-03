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

public protocol SeedProtocol: IdentityDigestable, Equatable, PrivateKeysDataProvider, URCodable, EnvelopeCodable {
    var data: Data { get }
    var name: String { get set }
    var note: String { get set }
    var creationDate: Date? { get set }
    var attachments: [Envelope] { get set }
    var outputDescriptor: OutputDescriptor? { get set }
    
    init?(data: DataProvider, name: String, note: String, creationDate: Date?, attachments: [Envelope], outputDescriptor: OutputDescriptor?)
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
    public static var cborTags = [Tag.seed, Tag.seedV1]
    
    public let data: Data
    public var name: String
    public var note: String
    public var creationDate: Date?
    public var attachments: [Envelope]
    public var outputDescriptor: OutputDescriptor?
    
    public init?(data: DataProvider, name: String = "", note: String = "", creationDate: Date? = nil, attachments: [Envelope] = [], outputDescriptor: OutputDescriptor? = nil) {
        let data = data.providedData
        guard data.count >= minSeedSize else {
            return nil
        }
        self.data = data
        self.name = name
        self.note = note
        self.creationDate = creationDate
        self.attachments = attachments
        self.outputDescriptor = outputDescriptor
    }
    
    public init?(data: DataProvider) {
        self.init(data: data, name: "", note: "", creationDate: nil, attachments: [], outputDescriptor: nil)
    }

    /// Copy constructor
    public init(_ seed: any SeedProtocol) {
        self.init(data: seed.data, name: seed.name, note: seed.note, creationDate: seed.creationDate, attachments: seed.attachments, outputDescriptor: seed.outputDescriptor)!
    }

    public init() {
        self.init(data: SecureRandomNumberGenerator.shared.data(count: minSeedSize))!
    }
    
    public static func == (lhs: Seed, rhs: Seed) -> Bool {
        lhs.data == rhs.data &&
        lhs.name == rhs.name &&
        lhs.creationDate == rhs.creationDate &&
        lhs.attachments.count == rhs.attachments.count &&
        zip(lhs.attachments, rhs.attachments).allSatisfy {
            $0.0.isEquivalent(to: $0.1)
        }
    }
}

extension Seed: TransactionResponseBody {
    public static var type = Envelope(.Seed)
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

public extension SeedProtocol {
    var untaggedCBOR: CBOR {
        var a: Map = [1: data]

        if let creationDate = creationDate {
            a[2] = creationDate
        }

        if !name.isEmpty {
            a[3] = name
        }

        if !note.isEmpty {
            a[4] = note
        }

        return CBOR.map(a)
    }
}

extension SeedProtocol {
    public init(untaggedCBOR: CBOR) throws {
        guard case CBOR.map(let map) = untaggedCBOR else {
            // CBOR doesn't contain a map.
            throw CBORError.invalidFormat
        }
        
        guard
            let dataItem = map.get(1),
            case let CBOR.bytes(bytes) = dataItem,
            !bytes.isEmpty
        else {
            // CBOR doesn't contain data field.
            throw CBORError.invalidFormat
        }
        let data = bytes.data
        
        let creationDate: Date?
        if let dateItem = map.get(2) {
            
            creationDate = try Date(cbor: dateItem)
        } else {
            creationDate = nil
        }

        let name: String
        if let nameItem = map.get(3) {
            guard case let CBOR.text(s) = nameItem else {
                // Name field doesn't contain string.
                throw CBORError.invalidFormat
            }
            name = s
        } else {
            name = ""
        }

        let note: String
        if let noteItem = map.get(4) {
            guard case let CBOR.text(s) = noteItem else {
                // Note field doesn't contain string.
                throw CBORError.invalidFormat
            }
            note = s
        } else {
            note = ""
        }
        self.init(data: data, name: name, note: note, creationDate: creationDate, attachments: [], outputDescriptor: nil)!
    }
}

extension SeedProtocol {
    public var identityDigestSource: Data {
        data
    }
}

public extension SeedProtocol {
    var envelope: Envelope {
        try! sizeLimitedEnvelope(nameLimit: .max, noteLimit: .max).0
            .addAssertions(attachments)
    }
    
    init(envelope: Envelope) throws {
        try envelope.checkType(.Seed)
        if
            let subjectLeaf = envelope.leaf,
            case CBOR.tagged(.seedV1, let item) = subjectLeaf
        {
            self = try Self.init(untaggedCBOR: item)
            return
        }

        let data = try envelope.extractSubject(Data.self)
        let name = (try? envelope.extractOptionalNonemptyString(forPredicate: .hasName)) ?? ""
        let note = (try? envelope.extractOptionalNonemptyString(forPredicate: .note)) ?? ""
        let creationDate = try envelope.extractOptionalObject(Date.self, forPredicate: .date)
        let attachments = try envelope.attachments()
        let outputDescriptor = try OutputDescriptor(
            envelope: envelope.optionalObject(forPredicate: .outputDescriptor)
        )
        guard let result = Self.init(data: data, name: name, note: note, creationDate: creationDate, attachments: attachments, outputDescriptor: outputDescriptor) else {
            throw EnvelopeError.invalidFormat
        }

        // This can't be properly checked unless we reconstruct possibly
        // elided `name` and `notes`.
//        guard result.envelope.isEquivalent(to: envelope) else {
//            throw EnvelopeError.invalidFormat
//        }

        self = result
    }
}

public extension SeedProtocol {
    func sizeLimitedEnvelope(nameLimit: Int, noteLimit: Int) -> (Envelope, Bool) {
        let e1 = Envelope(data)
            .addType(.Seed)
            .addAssertion(.date, creationDate)
            .addAssertion(.outputDescriptor, outputDescriptor?.envelope)
        
        let (e2, didElideName) = e1.addOptionalStringAssertionWithElisionLimit(.hasName, name, limit: nameLimit)

        let (e3, didElideNote) = e2.addOptionalStringAssertionWithElisionLimit(.note, note, limit: noteLimit)
        
        return (e3, didElideName || didElideNote)
    }
}
