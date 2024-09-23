//
//  PSBTSigningOrigin.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/10/21.
//

import Foundation

public struct PSBTSigningOrigin: CustomStringConvertible, Sendable {
    public let key: SecP256K1PublicKey
    public let path: DerivationPath
    
    public var description: String {
        "PSBTSigningOrigin(key: \(key), path: \(path))"
    }
    
    public func childKey(for parentKey: HDKey) -> SecP256K1PublicKey? {
        let parentKeyFingerprint = parentKey.originFingerprint ?? parentKey.keyFingerprint
        guard
            case .fingerprint(let originFingerprint) = path.origin,
            parentKeyFingerprint == originFingerprint,
            let childKey = try? HDKey(parent: parentKey, childDerivationPath: path).ecdsaPublicKey
        else {
            return nil
        }
        return childKey
    }
    
    public func canSign(with masterKey: HDKey) -> Bool {
        key == childKey(for: masterKey)
    }
    
    public func existingKnownSigner<SignerType: PSBTSigner>(signers: [SignerType], publicSigningKeys: Set<SecP256K1PublicKey>) -> SignerType? {
        for signer in signers {
            guard let key = childKey(for: signer.masterKey) else {
                continue
            }
            if publicSigningKeys.contains(key) {
                return signer
            }
        }
        return nil
    }
    
    public func possibleKnownSigner<SignerType: PSBTSigner>(signers: [SignerType]) -> SignerType? {
        for signer in signers {
            let childKey = childKey(for: signer.masterKey)
            if childKey == key {
                return signer
            }
        }
        return nil
    }
    
    public var isChange: Bool {
        path.isChange
    }
}

extension PSBTSigningOrigin {
    public func signingStatus<SignerType: PSBTSigner>(signers: [SignerType], publicSigningKeys: Set<SecP256K1PublicKey>) -> PSBTSigningStatus<SignerType> {
        if let existingSigner = existingKnownSigner(signers: signers, publicSigningKeys: publicSigningKeys) {
            return PSBTSigningStatus(origin: self, isSigned: true, knownSigner: existingSigner)
        } else if let possibleSigner = possibleKnownSigner(signers: signers) {
            return PSBTSigningStatus(origin: self, isSigned: false, knownSigner: possibleSigner)
        } else if publicSigningKeys.contains(key) {
            return PSBTSigningStatus(origin: self, isSigned: true, knownSigner: nil)
        } else {
            return PSBTSigningStatus(origin: self, isSigned: false, knownSigner: nil)
        }
    }
}
