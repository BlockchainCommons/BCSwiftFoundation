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
        case ecCompressedPublicKey(ECPublicKey)
        case ecUncompressedPublicKey(ECUncompressedPublicKey)
        //case ecXOnlyPublicKey(ECXOnlyPublicKey)
        case wif(WIF)
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
}

extension DescriptorKeyExpression {
    func pubKeyData(
        wildcardChildNum: UInt32?,
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
            data = k.key.public.data
        case .hdKey(let k):
            guard let k2 = try? HDKey(parent: k, childDerivationPath: k.children, wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) else {
                return nil
            }
            data = k2.ecPublicKey.data
        }
        return data
    }
    
    var requiresWildcardChildNum: Bool {
        guard case let .hdKey(k) = key else {
            return false
        }
        return k.requiresWildcardChildNum
    }
}

extension DescriptorKeyExpression : CustomStringConvertible {
    var description: String {
        var comps: [String] = []
        if let origin = origin, !origin.isEmpty {
            comps.append("[\(origin)]")
        }
        comps.append(key.description)
        return comps.joined()
    }
}

extension DescriptorKeyExpression.Key : CustomStringConvertible {
    var description: String {
        switch self {
        case .ecCompressedPublicKey(let key):
            return key.data.hex
        case .ecUncompressedPublicKey(let key):
            return key.data.hex
        // case .ecXOnlyPublicKey(let key):
        //    return key.data.hex
        case .wif(let key):
            return key.description
        case .hdKey(let key):
            return key.description(withChildren: true)
        }
    }
}
