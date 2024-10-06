//
//  DescriptorKeyExpression.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation

struct DescriptorKeyExpression {
    let origin: DerivationPath?
    let key: Key

    enum Key {
        case ecCompressedPublicKey(any SecP256K1PublicKeyProtocol)
        case ecUncompressedPublicKey(SecP256K1UncompressedPublicKey)
        //case ecXOnlyPublicKey(SchnorrPublicKey)
        case wif(ECPrivateKey)
        case hdKey(HDKey)
    }
    
    var taggedCBOR: CBOR {
        switch key {
        case .ecCompressedPublicKey(let k):
            return k.taggedCBOR
        case .ecUncompressedPublicKey(let k):
            return k.taggedCBOR
        case .wif(let k):
            return k.taggedCBOR
        case .hdKey(let k):
            return k.taggedCBOR
        }
    }
    
    var compactCBOR: CBOR? {
        switch key {
        case .ecCompressedPublicKey(let k):
            return k.taggedCBOR
        case .ecUncompressedPublicKey(let k):
            return k.taggedCBOR
        case .wif(let k):
            return k.taggedCBOR
        case .hdKey(let k):
            return k.taggedCBOR
        }
    }
}

extension DescriptorKeyExpression {
    func pubKeyData(
        chain: Chain?,
        addressIndex: UInt32?,
        privateKeyProvider: PrivateKeyProvider?
    ) -> Data? {
        let data: Data
        switch key {
        case .ecCompressedPublicKey(let k):
            data = k.data
        case .ecUncompressedPublicKey(let k):
            data = k.data
        // case .ecXOnlyPublicKey(let k):
        //     data = k.data
        case .wif(let k):
            data = k.secp256k1PublicKey.data
        case .hdKey(let k):
            guard let k2 = try? HDKey(parent: k, childDerivationPath: k.children, chain: chain, addressIndex: addressIndex, privateKeyProvider: privateKeyProvider) else {
                return nil
            }
            data = k2.ecdsaPublicKey.data
        }
        return data
    }

    func hdKey(
        keyType: KeyType,
        chain: Chain?,
        addressIndex: UInt32?,
        privateKeyProvider: PrivateKeyProvider?
    ) -> HDKey? {
        guard
            case let .hdKey(k) = key,
            let k2 = try? HDKey(parent: k, derivedKeyType: keyType, childDerivationPath: k.children, chain: chain, addressIndex: addressIndex, privateKeyProvider: privateKeyProvider)
        else {
            return nil
        }
        return k2
    }

    var baseKey: HDKey? {
        guard case let .hdKey(hdKey) = key else {
            return nil
        }
        return hdKey
    }

    var requiresAddressIndex: Bool {
        guard case let .hdKey(k) = key else {
            return false
        }
        return k.requiresAddressIndex
    }
    
    var requiresChain: Bool {
        guard case let .hdKey(k) = key else {
            return false
        }
        return k.requiresChain
    }
}

extension DescriptorKeyExpression : CustomStringConvertible {
    var description: String {
        self.description()
    }
}

extension DescriptorKeyExpression {
    func description(withChildren: Bool = true) -> String {
        var comps: [String] = []
        if let origin = origin, !origin.isEmpty {
            comps.append("[\(origin)]")
        }
        comps.append(key.description(withChildren: withChildren))
        return comps.joined()
    }
}

extension DescriptorKeyExpression.Key : CustomStringConvertible {
    var description: String {
        self.description()
    }
}

extension DescriptorKeyExpression.Key {
    func description(withChildren: Bool = true) -> String {
        switch self {
        case .ecCompressedPublicKey(let key):
            return key.data.hex
        case .ecUncompressedPublicKey(let key):
            return key.data.hex
        // case .ecXOnlyPublicKey(let key):
        //    return key.data.hex
        case .wif(let key):
            return key.wif
        case .hdKey(let key):
            return key.description(withChildren: withChildren)
        }
    }
}
