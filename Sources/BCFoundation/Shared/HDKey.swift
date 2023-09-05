//
//  HDKey.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/4/21.
//

import Foundation
import WolfBase
import URKit

public enum HDKeyError: Error {
    case invalidSeed
    case invalidBase58
    case cannotDerivePrivateFromPublic
    case cannotDeriveHardenedFromPublic
    case cannotDeriveFromNonDerivable
    case cannotDeriveInspecificStep
    case invalidDepth
    case unknownDerivationError
}

public protocol HDKeyProtocol: IdentityDigestable, Equatable, URCodable, EnvelopeCodable {
    var isMaster: Bool { get }
    var keyType: KeyType { get }
    var keyData: Data { get }
    var chainCode: Data? { get }
    var useInfo: UseInfo { get }
    var parent: DerivationPath { get }
    var children: DerivationPath { get }
    var parentFingerprint: UInt32? { get }
    var name: String { get set }
    var note: String { get set }

    init(isMaster: Bool, keyType: KeyType, keyData: Data, chainCode: Data?, useInfo: UseInfo, parent: DerivationPath?, children: DerivationPath?, parentFingerprint: UInt32?, name: String, note: String)
    init(_ key: any HDKeyProtocol)
}

public struct HDKey: HDKeyProtocol {
    public static var cborTag: Tag = .hdKey
    
    public let isMaster: Bool
    public let keyType: KeyType
    public let keyData: Data
    public let chainCode: Data?
    public let useInfo: UseInfo
    public let parent: DerivationPath
    public let children: DerivationPath
    public let parentFingerprint: UInt32?
    public var name: String
    public var note: String
    
    public init(isMaster: Bool, keyType: KeyType, keyData: Data, chainCode: Data?, useInfo: UseInfo, parent: DerivationPath?, children: DerivationPath?, parentFingerprint: UInt32?, name: String = "", note: String = "") {
        self.isMaster = isMaster
        self.keyType = keyType
        self.keyData = keyData
        self.chainCode = chainCode
        self.useInfo = useInfo
        self.parent = parent ?? .init()
        self.children = children ?? .init()
        self.parentFingerprint = parentFingerprint
        self.name = name
        self.note = note
    }

    // Copy constructor
    public init(_ key: any HDKeyProtocol) {
        self.isMaster = key.isMaster
        self.keyType = key.keyType
        self.keyData = key.keyData
        self.chainCode = key.chainCode
        self.useInfo = key.useInfo
        self.parent = key.parent
        self.children = key.children
        self.parentFingerprint = key.parentFingerprint
        self.name = key.name
        self.note = key.note
    }
}

extension HDKey: TransactionResponseBody {
    public static let type = Envelope(.BIP32Key)
}

extension HDKeyProtocol {
    public init(key: any HDKeyProtocol, derivedKeyType: KeyType? = nil, isDerivable: Bool = true, parent: DerivationPath? = nil, children: DerivationPath? = nil) throws {
        let derivedKeyType = derivedKeyType ?? key.keyType
        
        guard key.keyType == .private || derivedKeyType == .public else {
            // public -> private
            throw HDKeyError.cannotDerivePrivateFromPublic
        }

        let keyData: Data
        if key.keyType == derivedKeyType {
            // private -> private
            // public -> public
            keyData = key.keyData
        } else {
            // private -> public
            keyData = key.wallyExtKey.pubKey
        }
        
        let effectiveParent: DerivationPath
        if let parent {
            effectiveParent = parent
        } else {
            if key.isMaster && derivedKeyType == .public {
                effectiveParent = DerivationPath(origin: .fingerprint(key.keyFingerprint), depth: 0)
            } else {
                effectiveParent = key.parent
            }
        }
        let chainCode = isDerivable ? key.chainCode : nil
        let isMaster = key.isMaster &&
            (derivedKeyType == .private) &&
            effectiveParent.isMaster &&
            chainCode != nil &&
            key.parentFingerprint == nil
        
        self.init(
            isMaster: isMaster,
            keyType: derivedKeyType,
            keyData: keyData,
            chainCode: chainCode,
            useInfo: key.useInfo,
            parent: effectiveParent,
            children: children ?? key.children,
            parentFingerprint: key.parentFingerprint,
            name: "",
            note: ""
        )
    }
    
    public init(wallyExtKey key: WallyExtKey, useInfo: UseInfo? = nil, parent: DerivationPath? = nil, children: DerivationPath? = nil) throws {
        let keyData: Data
        if key.isPrivate {
            keyData = key.privKey
        } else {
            keyData = key.pubKey
        }

        let steps: [BasicDerivationStep]
        if key.childNum == 0 {
            steps = []
        } else {
            steps = [BasicDerivationStep(rawValue: key.childNum)]
        }
        let newParent: DerivationPath
        if let parent = parent {
            newParent = parent
        } else {
            let o = DerivationPath.Origin.fingerprint(Wally.fingerprint(for: key))
            newParent = DerivationPath(steps: steps, origin: o, depth: Int(key.depth))
        }
        
        let useInfo = useInfo ?? .init()
        
        self.init(
            isMaster: key.isMaster,
            keyType: KeyType(isPrivate: key.isPrivate),
            keyData: keyData,
            chainCode: key.chainCode,
            useInfo: UseInfo(asset: useInfo.asset, network: key.network!),
            parent: parent ?? newParent,
            children: children,
            parentFingerprint: deserialize(UInt32.self, key.parent160)!,
            name: "",
            note: ""
        )
    }

    public init(base58: String, useInfo: UseInfo? = nil, parent: DerivationPath? = nil, children: DerivationPath? = nil, overrideOriginFingerprint: UInt32? = nil) throws {
        guard let key = Wally.hdKey(fromBase58: base58) else {
            throw HDKeyError.invalidBase58
        }
        let isMaster: Bool
        if let parent = parent {
            isMaster = parent.isMaster
        } else {
            isMaster = key.isMaster
        }
        let keyData: Data
        if key.isPrivate {
            keyData = key.privKey
        } else {
            keyData = key.pubKey
        }
        
        let newParent: DerivationPath
        if let parent = parent {
            newParent = parent
        } else {
            let steps: [BasicDerivationStep]
            if key.childNum == 0 {
                steps = []
            } else {
                steps = [BasicDerivationStep(rawValue: key.childNum)]
            }
            let originFingerprint = overrideOriginFingerprint ?? Wally.fingerprint(for: key)
            let o = DerivationPath.Origin.fingerprint(originFingerprint)
            newParent = DerivationPath(steps: steps, origin: o, depth: Int(key.depth))
        }
        let parentFingerprint: UInt32?
        if isMaster {
            parentFingerprint = nil
        } else {
            parentFingerprint = deserialize(UInt32.self, key.parent160)!
        }
        let useInfo = useInfo ?? .init()
        self.init(
            isMaster: isMaster,
            keyType: KeyType(isPrivate: key.isPrivate),
            keyData: keyData,
            chainCode: key.chainCode,
            useInfo: UseInfo(asset: useInfo.asset, network: key.network!),
            parent: newParent,
            children: children,
            parentFingerprint: parentFingerprint,
            name: "",
            note: ""
        )
    }
    
    public init(bip39Seed: BIP39.Seed, useInfo: UseInfo? = nil, children: DerivationPath? = nil) throws {
        let useInfo = useInfo ?? .init()
        guard let key = Wally.hdKey(bip39Seed: bip39Seed.data, network: useInfo.network) else {
            // From libwally-core docs:
            // The entropy passed in may produce an invalid key. If this happens, WALLY_ERROR will be returned
            // and the caller should retry with new entropy.
            throw HDKeyError.invalidSeed
        }
        self.init(
            isMaster: true,
            keyType: .private,
            keyData: key.privKey,
            chainCode: key.chainCode,
            useInfo: useInfo,
            parent: DerivationPath(origin: .master),
            children: children,
            parentFingerprint: nil,
            name: "",
            note: ""
        )
    }
    
    public init(seed: any SeedProtocol, useInfo: UseInfo? = nil, children: DerivationPath? = nil) throws {
        try self.init(bip39Seed: BIP39.Seed(bip39: seed.bip39), useInfo: useInfo, children: children)
    }

    public init(parent: any HDKeyProtocol, derivedKeyType: KeyType? = nil, childDerivation: any DerivationStep, chain: Chain? = nil, addressIndex: UInt32? = nil) throws {
        let derivedKeyType = derivedKeyType ?? parent.keyType
        
        guard parent.keyType == .private || derivedKeyType == .public else {
            throw HDKeyError.cannotDerivePrivateFromPublic
        }
        guard parent.isDerivable else {
            throw HDKeyError.cannotDeriveFromNonDerivable
        }
                
        guard let childNum = childDerivation.rawValue(chain: chain, addressIndex: addressIndex) else {
            throw HDKeyError.cannotDeriveInspecificStep
        }
        guard let derivedKey = Wally.key(from: parent.wallyExtKey, childNum: childNum, isPrivate: derivedKeyType.isPrivate) else {
            throw HDKeyError.unknownDerivationError
        }
                
        let origin: DerivationPath
        let parentOrigin = parent.parent
        var steps = parentOrigin.steps
        steps.append(childDerivation.resolve(chain: chain, addressIndex: addressIndex)!)
        let sourceFingerprint = parentOrigin.originFingerprint ?? parent.keyFingerprint
        let depth: Int
        if let parentDepth = parentOrigin.depth {
            depth = parentDepth + 1
        } else {
            depth = 1
        }
        origin = DerivationPath(steps: steps, origin: .fingerprint(sourceFingerprint), depth: depth)
        self.init(
            isMaster: false,
            keyType: derivedKeyType,
            keyData: derivedKeyType == .private ? derivedKey.privKey : derivedKey.pubKey,
            chainCode: derivedKey.chainCode,
            useInfo: parent.useInfo,
            parent: origin,
            children: nil,
            parentFingerprint: parent.keyFingerprint,
            name: "",
            note: ""
        )
    }
    
    public init(parent: any HDKeyProtocol, derivedKeyType: KeyType? = nil, childDerivationPath: DerivationPath, isDerivable: Bool = true, chain: Chain? = nil, addressIndex: UInt32? = nil, privateKeyProvider: PrivateKeyProvider? = nil, children: DerivationPath? = nil) throws {
        let derivedKeyType = derivedKeyType ?? parent.keyType
        
        guard parent.isDerivable else {
            throw HDKeyError.cannotDeriveFromNonDerivable
        }

        var effectiveDerivationPath = childDerivationPath
        if effectiveDerivationPath.origin != nil {
            let parentDepth = parent.parent.effectiveDepth
            guard let p = childDerivationPath.dropFirst(parentDepth) else {
                throw HDKeyError.invalidDepth
            }
            effectiveDerivationPath = p
        }

        var workingKey = parent
        if parent.keyType == .public {
            if derivedKeyType == .private {
                guard
                    let privateKeyProvider = privateKeyProvider,
                    let privateKey = try privateKeyProvider(workingKey),
                    privateKey.isPrivate
                else {
                    throw HDKeyError.cannotDerivePrivateFromPublic
                }
                workingKey = privateKey
            } else if effectiveDerivationPath.isHardened {
                guard
                    let privateKeyProvider = privateKeyProvider,
                    let privateKey = try privateKeyProvider(workingKey),
                    privateKey.isPrivate
                else {
                    throw HDKeyError.cannotDeriveHardenedFromPublic
                }
                workingKey = privateKey
            }
        }

        var derivedKey = workingKey
        for step in effectiveDerivationPath.steps {
            derivedKey = try HDKey(parent: derivedKey, derivedKeyType: derivedKey.keyType, childDerivation: step, chain: chain, addressIndex: addressIndex)
        }
        derivedKey = try HDKey(key: derivedKey, derivedKeyType: derivedKeyType)
        self.init(
            isMaster: derivedKey.isMaster,
            keyType: derivedKeyType,
            keyData: derivedKey.keyData,
            chainCode: isDerivable ? derivedKey.chainCode : nil,
            useInfo: parent.useInfo,
            parent: derivedKey.parent,
            children: children ?? derivedKey.children,
            parentFingerprint: derivedKey.parentFingerprint,
            name: "",
            note: ""
        )
    }
    
    public var isPrivate: Bool {
        keyType.isPrivate
    }
    
    public var isDerivable: Bool {
        chainCode != nil
    }

    public var requiresAddressIndex: Bool {
        children.hasWildcard
    }
    
    public var requiresChain: Bool {
        children.hasPair
    }

    public var originFingerprint: UInt32? {
        parent.originFingerprint
    }
    
    public var keyFingerprintData: Data {
        Wally.fingerprintData(for: wallyExtKey)
    }

    public var keyFingerprint: UInt32 {
        Wally.fingerprint(for: wallyExtKey)
    }
    
    public var `public`: HDKey {
        try! HDKey(key: self, derivedKeyType: .public)
    }
    
    public var base58: String {
        base58PrivateKey ?? base58PublicKey ?? "invalid"
    }
    
    public var base58PublicKey: String? {
        Wally.base58(from: wallyExtKey, isPrivate: false)
    }
    
    public var base58PrivateKey: String? {
        Wally.base58(from: wallyExtKey, isPrivate: true)
    }
    
    public var ecPublicKey: ECPublicKey {
        ECPublicKey(wallyExtKey.pubKey)!
    }

    public var ecPrivateKey: ECPrivateKey? {
        if !isPrivate {
            return nil
        }
        var data = wallyExtKey.privKey
        // skip prefix byte 0
        precondition(data.popFirst() != nil)
        return ECPrivateKey(data)!
    }

    public var wallyExtKey: WallyExtKey {
        var k = WallyExtKey()
        
        let effectiveDepth = parent.effectiveDepth
        if effectiveDepth > 0 {
            k.depth = UInt8(effectiveDepth)
            
            if let lastStep = parent.steps.last as? BasicDerivationStep,
               case let ChildIndexSpec.index(childIndex) = lastStep.childIndexSpec {
                let value = childIndex.value
                let isHardened = lastStep.isHardened
                let childNum = value | (isHardened ? 0x80000000 : 0)
                k.childNum = childNum
            }
        }
        
        switch keyType {
        case .private:
            k.privKey = keyData
            Wally.updatePublicKey(in: &k)
            switch useInfo.network {
            case .mainnet:
                k.version = WallyExtKey.versionMainPrivate
            case .testnet:
                k.version = WallyExtKey.versionTestPrivate
            }
        case .public:
            var privKey = k.privKey
            privKey[0] = 0x01
            k.privKey = privKey
            k.pubKey = keyData
            switch useInfo.network {
            case .mainnet:
                k.version = WallyExtKey.versionMainPublic
            case .testnet:
                k.version = WallyExtKey.versionTestPublic
            }
        }
        
        Wally.updateHash160(in: &k)
        
        if let chainCode = chainCode {
            k.chainCode = chainCode
        }
        
        if let parentFingerprint = parentFingerprint {
            k.parent160 = parentFingerprint.serialized
        }
        
        k.checkValid()
        return k
    }

    public func description(withParent: Bool = false, withChildren: Bool = false) -> String {
        var comps: [String] = []
        if withParent && !parent.isEmpty {
            comps.append("[\(parent)]")
        }
        comps.append(base58)
        if withChildren && !children.isEmpty {
            comps.append("/\(children)")
        }
        return comps.joined()
    }

    public var fullDescription: String {
        description(withParent: true, withChildren: true)
    }
}

extension HDKeyProtocol {
    public func cbor(nameLimit: Int = .max, noteLimit: Int = .max) -> (CBOR, Bool) {
        var a = Map()
        var didLimit: Bool = false

        if isMaster {
            a[1] = true
        }

        if !isMaster && keyType == .private {
            a[2] = true
        }

        a[3] = keyData.cbor

        if let chainCode = chainCode {
            a[4] = chainCode.cbor
        }

        if !useInfo.isDefault {
            a[5] = useInfo.taggedCBOR
        }

        if !parent.isEmpty || parent.originFingerprint != nil {
            a[6] = parent.taggedCBOR
        }

        if !children.isEmpty {
            a[7] = children.taggedCBOR
        }

        if let parentFingerprint = parentFingerprint {
            a[8] = parentFingerprint.cbor
        }
        
        if !name.isEmpty {
            let limitedName = name.prefix(count: nameLimit)
            didLimit = didLimit || limitedName.count < name.count
            a[9] = limitedName.cbor
        }

        if !note.isEmpty {
            let limitedNote = note.prefix(count: noteLimit)
            didLimit = didLimit || limitedNote.count < note.count
            a[10] = limitedNote.cbor
        }

        return (a.cbor, didLimit)
    }

    public func sizeLimitedUR(nameLimit: Int = 100, noteLimit: Int = 500) -> (UR, Bool) {
        let (c, didLimit) = cbor(nameLimit: nameLimit, noteLimit: noteLimit)
        return try! (UR(type: Tag.hdKey.name!, untaggedCBOR: c), didLimit)
    }
}

extension HDKeyProtocol {
    public var untaggedCBOR: CBOR {
        cbor().0
    }
    
    public init(untaggedCBOR cbor: CBOR) throws {
        guard case CBOR.map(let map) = cbor
        else {
            // Doesn't contain a map.
            throw CBORError.invalidFormat
        }

        let isMaster = try Bool(cbor: map[1]) ?? false
        let isPrivate = try Bool(cbor: map[2]) ?? isMaster

        guard
            let keyData = try Data(cbor: map[3]),
            keyData.count == 33
        else {
            // Invalid key data.
            throw CBORError.invalidFormat
        }

        let chainCode = try Data(cbor: map[4])
        if let chainCode {
            guard chainCode.count == 32 else {
                // Invalid key chain code.
                throw CBORError.invalidFormat
            }
        }

        let useInfo: UseInfo
        if let useInfoItem = map[5] {
            useInfo = try UseInfo(taggedCBOR: useInfoItem)
        } else {
            useInfo = UseInfo()
        }

        let origin: DerivationPath?
        if let originItem = map[6] {
            origin = try DerivationPath(taggedCBOR: originItem)
        } else {
            origin = nil
        }

        let children: DerivationPath?
        if let childrenItem = map[7] {
            children = try DerivationPath(taggedCBOR: childrenItem)
        } else {
            children = nil
        }

        let parentFingerprint: UInt32?
        if let parentFingerprintItem = map[8] {
            guard
                case let CBOR.unsigned(parentFingerprintValue) = parentFingerprintItem,
                parentFingerprintValue > 0,
                parentFingerprintValue <= UInt32.max
            else {
                // Invalid parent fingerprint.
                throw CBORError.invalidFormat
            }
            parentFingerprint = UInt32(parentFingerprintValue)
        } else {
            parentFingerprint = nil
        }

        let name: String
        if let nameItem = map[9] {
            guard case let CBOR.text(s) = nameItem else {
                // Name field doesn't contain string.
                throw CBORError.invalidFormat
            }
            name = s
        } else {
            name = ""
        }

        let note: String
        if let noteItem = map[10] {
            guard case let CBOR.text(s) = noteItem else {
                // Note field doesn't contain string.
                throw CBORError.invalidFormat
            }
            note = s
        } else {
            note = ""
        }

        let keyType: KeyType = isPrivate ? .private : .public

        self.init(HDKey(isMaster: isMaster, keyType: keyType, keyData: keyData, chainCode: chainCode, useInfo: useInfo, parent: origin, children: children, parentFingerprint: parentFingerprint, name: name, note: note))
    }
}

public extension HDKeyProtocol {
    var identityDigestSource: Data {
        var result: [CBOR] = []

        result.append(keyData.cbor)

        if let chainCode = chainCode {
            result.append(chainCode.cbor)
        } else {
            result.append(CBOR.null)
        }

        result.append(useInfo.asset.rawValue.cbor)
        result.append(useInfo.network.rawValue.cbor)

        return result.cborData
    }
}

public extension HDKeyProtocol {
    var envelope: Envelope {
        sizeLimitedEnvelope(nameLimit: .max, noteLimit: .max).0
    }
    
    init(_ envelope: Envelope) throws {
        if
            let subjectLeaf = envelope.leaf,
            case CBOR.tagged(.hdKey, let item) = subjectLeaf
        {
            self = try Self(untaggedCBOR: item)
            return
        }
        
        let isMaster = envelope.hasType(.MasterKey)
        let isPrivate = envelope.hasType(.PrivateKey)
        let isPublic = envelope.hasType(.PublicKey)
        let keyData = try envelope.extractSubject(Data.self)
        let chainCode = try envelope.extractOptionalObject(Data.self, forPredicate: .chainCode)
        let useInfo = try UseInfo(envelope.object(forPredicate: .asset))
        let parent = try DerivationPath(envelope.optionalObject(forPredicate: .parentPath))
        let children = try DerivationPath(envelope.optionalObject(forPredicate: .childrenPath))
        let parentFingerprint = try envelope.extractOptionalObject(UInt32.self, forPredicate: .parentFingerprint)
        let name = try envelope.extractOptionalObject(String.self, forPredicate: .hasName) ?? ""
        let note = try envelope.extractOptionalObject(String.self, forPredicate: .note) ?? ""
        let keyType: KeyType = isPrivate ? .private : .public
        guard
            isPrivate || isPublic,
            !(isPublic && isMaster),
            !(isMaster && parent != nil),
            !(isMaster && parentFingerprint != nil)
        else {
            throw EnvelopeError.invalidFormat
        }
        self.init(isMaster: isMaster, keyType: keyType, keyData: keyData, chainCode: chainCode, useInfo: useInfo, parent: parent, children: children, parentFingerprint: parentFingerprint, name: name, note: note)
        guard self.envelope.isEquivalent(to: envelope) else {
            throw EnvelopeError.invalidFormat
        }
    }
}

public extension HDKeyProtocol {
    func sizeLimitedEnvelope(nameLimit: Int = 100, noteLimit: Int = 500) -> (Envelope, Bool) {
        var e = Envelope(keyData)
            .addType(.BIP32Key)
            .addType(keyType.envelope)
            .addType(if: isMaster, .MasterKey)
            .addAssertion(.asset, useInfo.envelope)
            .addAssertion(.chainCode, chainCode)
            .addAssertion(if: !parent.isEmpty, .parentPath, parent.envelope)
            .addAssertion(if: !children.isEmpty, .childrenPath, children.envelope)
            .addAssertion(.parentFingerprint, parentFingerprint)
        
        var didLimit = false
        
        if !name.isEmpty {
            let limitedName = name.prefix(count: nameLimit)
            didLimit = didLimit || limitedName.count < name.count
            e = e.addAssertion(if: !name.isEmpty, .hasName, name)
        }
        
        if !note.isEmpty {
            let limitedNote = note.prefix(count: noteLimit)
            didLimit = didLimit || limitedNote.count < note.count
            e = e.addAssertion(if: !note.isEmpty, .note, note)
        }

        return (e, didLimit)
    }
}
