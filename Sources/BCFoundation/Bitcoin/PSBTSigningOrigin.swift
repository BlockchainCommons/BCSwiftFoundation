//
//  PSBTSigningOrigin.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/10/21.
//

import Foundation

public struct PSBTSigningOrigin: CustomStringConvertible {
    public let key: ECCompressedPublicKey
    public let path: DerivationPath
    
    public var description: String {
        "PSBTSigningOrigin(key: \(key), path: \(path))"
    }
    
    public func childKey(for masterKey: HDKey) -> ECCompressedPublicKey? {
        guard
            let masterKeyFingerprint = masterKey.originFingerprint,
            case .fingerprint(let originFingerprint) = path.origin,
            masterKeyFingerprint == originFingerprint,
            let childKey = try? HDKey(parent: masterKey, childDerivationPath: path).ecPublicKey
        else {
            return nil
        }
        return childKey
    }
    
    public func canSign(with masterKey: HDKey) -> Bool {
        key == childKey(for: masterKey)
    }
    
    public var isChange: Bool {
        path.isChange
    }
}

extension PSBTSigningOrigin {
    public func signingStatus<SignerType: PSBTSigner>(seeds: [SignerType], signatures: Set<ECCompressedPublicKey>) -> PSBTSigningStatus<SignerType> {
        if let seed = seeds.first(where: {
            guard let key = childKey(for: $0.masterKey) else {
                return false
            }
            return signatures.contains(key)
        }) {
            return PSBTSigningStatus(origin: self, isSigned: true, knownSigner: seed)
        } else if let seed = seeds.first(where: { canSign(with: $0.masterKey)} ) {
            return PSBTSigningStatus(origin: self, isSigned: false, knownSigner: seed)
        } else if signatures.contains(key) {
            return PSBTSigningStatus(origin: self, isSigned: true, knownSigner: nil)
        } else {
            return PSBTSigningStatus(origin: self, isSigned: false, knownSigner: nil)
        }
    }
}
