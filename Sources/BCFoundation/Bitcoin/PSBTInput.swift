//
//  PSBTInput.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation
import WolfBase

public struct PSBTInput {
    public let origins: [PSBTSigningOrigin]
    public let signatures: [SecP256K1PublicKey: Data]
    public let witnessStack: [ScriptPubKey?]
    public let isSegwit: Bool
    public let amount: Satoshi?

    init(wallyInput: WallyPSBTInput) {
        if wallyInput.keyPaths.count > 0 {
            self.origins = getOrigins(keypaths: wallyInput.keyPaths)
        } else {
            self.origins = []
        }

        if(wallyInput.signatures.count > 0) {
            self.signatures = getSignatures(signatures: wallyInput.signatures)
        } else {
            self.signatures = [:]
        }
        
        var witnessStack: [ScriptPubKey?] = []
        if let wallyWitnessStack = wallyInput.finalWitness {
            let numItems = wallyWitnessStack.count
            for i in 0 ..< numItems {
                let witnessItem = wallyWitnessStack[i]
                if let witnessData = witnessItem.witness {
                    let witnessScript = ScriptPubKey(Script(witnessData))
                    witnessStack.append(witnessScript)
                } else {
                    witnessStack.append(nil)
                }
            }
        }
        self.witnessStack = witnessStack

//        if let witnessScript = wallyInput.witness_script {
//            self.witnessScript = ScriptPubKey(Script(Data(bytes: witnessScript, count: wallyInput.witness_script_len)))
//        } else {
//            self.witnessScript = nil
//        }

        if let witnessUTXO = wallyInput.witnessUTXO {
            isSegwit = true
            amount = witnessUTXO.satoshi
        } else {
            isSegwit = false
            amount = nil
        }
    }

    // Can we provide at least one signature, assuming we have the private key?
    public func signableOrigins(with masterKey: HDKey) -> [PSBTSigningOrigin] {
        origins.filter {
            $0.canSign(with: masterKey)
        }
    }

    public func canSign(with masterKey: HDKey) -> Bool {
        !signableOrigins(with: masterKey).isEmpty
    }

    // Can we provide at least one signature, assuming we have the private key?
    public func originsSigned(by masterKey: HDKey) -> [PSBTSigningOrigin] {
        guard let masterKeyFingerprint = masterKey.originFingerprint else {
            return []
        }

        var result: [PSBTSigningOrigin] = []
        for origin in origins {
            let path = origin.path
            if
                case .fingerprint(let originFingerprint) = path.origin,
                masterKeyFingerprint == originFingerprint,
                let childKey = try? HDKey(parent: masterKey, childDerivationPath: path).ecdsaPublicKey,
                signatures.keys.contains(childKey)
            {
                result.append(origin)
            }
        }
        return result
    }
    
    public func isSigned(by masterKey: HDKey) -> Bool {
        !originsSigned(by: masterKey).isEmpty
    }

    public func address(network: Network) -> String? {
        guard
            !witnessStack.isEmpty,
            let scriptPubKey = witnessStack[0]
        else {
            return nil
        }
        return Bitcoin.Address(scriptPubKey: scriptPubKey, network: network)!.description
    }
    
    public var isFullySigned: Bool {
        let signatureKeys: Set<SecP256K1PublicKey> = Set(signatures.keys)
        return origins.allSatisfy { origin in
            signatureKeys.contains(origin.key)
        }
    }
}

extension PSBTInput: CustomStringConvertible {
    public var description: String {
        "PSBTInput(origins: \(origins), signatures: \(signatures), witnessStack: \(witnessStack), isSegwit: \(isSegwit), amount: \((amount?.btcFormat)†))"
    }
}

func getOrigins(keypaths: WallyMap) -> [PSBTSigningOrigin] {
    var result: [PSBTSigningOrigin] = []
    for i in 0..<keypaths.count {
        // TOOD: simplify after https://github.com/ElementsProject/libwally-core/issues/241
        let item = keypaths[i]

        let pubKey = SecP256K1PublicKey(item.key)!
        let itemValue = item.value
        let fingerprint = deserialize(UInt32.self, itemValue)!
        let keyPath = itemValue.subdata(in: WallyExtKey.keyFingerprintLen..<itemValue.count)

        var components: [UInt32] = []
        for j in 0..<keyPath.count / 4 {
            let range = (j * 4)..<((j + 1) * 4)
            let subdata = keyPath[range]
            let component = subdata.withUnsafeBytes{ $0.load(as: UInt32.self) }
            components.append(component)
        }
        let path = DerivationPath(rawPath: components, origin: .fingerprint(fingerprint))!
        result.append(PSBTSigningOrigin(key: pubKey, path: path))
    }
    return result
}

func getSignatures(signatures: WallyMap) -> [SecP256K1PublicKey: Data] {
    var result: [SecP256K1PublicKey: Data] = [:]
    for i in 0 ..< signatures.count {
        let item = signatures[i]
        let pubKey = SecP256K1PublicKey(item.key)!
        result[pubKey] = item.value
    }
    return result
}

extension PSBTInput {
    public func signingStatus<SignerType: PSBTSigner>(signers: [SignerType]) -> [PSBTSigningStatus<SignerType>] {
        let publicSigningKeys = Set(signatures.map { $0.key })
        var result: [PSBTSigningStatus<SignerType>] = []
        for origin in origins {
            let status = origin.signingStatus(signers: signers, publicSigningKeys: publicSigningKeys)
            result.append(status)
        }
        return result
    }
}
