//
//  PSBTInput.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation
import WolfBase
import BCWally

public struct PSBTInput {
    public let origins: [PSBTSigningOrigin]
    public let signatures: [ECCompressedPublicKey: Data]
    public let witnessScript: ScriptPubKey?
    public let isSegwit: Bool
    public let amount: Satoshi?

    init(wallyInput: WallyPSBTInput) {
        if wallyInput.keypaths.num_items > 0 {
            self.origins = getOrigins(keypaths: wallyInput.keypaths)
        } else {
            self.origins = []
        }

        if(wallyInput.signatures.num_items > 0) {
            self.signatures = getSignatures(signatures: wallyInput.signatures)
        } else {
            self.signatures = [:]
        }

        if let witnessScript = wallyInput.witness_script {
            self.witnessScript = ScriptPubKey(Script(Data(bytes: witnessScript, count: wallyInput.witness_script_len)))
        } else {
            self.witnessScript = nil
        }

        if let witness_utxo = wallyInput.witness_utxo {
            isSegwit = true
            amount = witness_utxo.pointee.satoshi
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
                let childKey = try? HDKey(parent: masterKey, childDerivationPath: path).ecPublicKey,
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
        guard let scriptPubKey = witnessScript else {
            return nil
        }
        return Bitcoin.Address(scriptPubKey: scriptPubKey, network: network)!.description
    }
    
    public var isFullySigned: Bool {
        let signatureKeys: Set<ECCompressedPublicKey> = Set(signatures.keys)
        return origins.allSatisfy { origin in
            signatureKeys.contains(origin.key)
        }
    }
}

extension PSBTInput: CustomStringConvertible {
    public var description: String {
        "PSBTInput(origins: \(origins), signatures: \(signatures), witnessScript: \(witnessScript†), isSegwit: \(isSegwit), amount: \((amount?.btcFormat)†))"
    }
}

func getOrigins(keypaths: wally_map) -> [PSBTSigningOrigin] {
    var result: [PSBTSigningOrigin] = []
    for i in 0..<keypaths.num_items {
        // TOOD: simplify after https://github.com/ElementsProject/libwally-core/issues/241
        let item: wally_map_item = keypaths.items[i]

        let pubKey = ECCompressedPublicKey(Data(bytes: item.key, count: Int(EC_PUBLIC_KEY_LEN)))!
        let fingerprintData = Data(bytes: item.value, count: Int(BIP32_KEY_FINGERPRINT_LEN))
        let fingerprint = deserialize(UInt32.self, fingerprintData)!
        let keyPath = Data(bytes: item.value + Int(BIP32_KEY_FINGERPRINT_LEN), count: Int(item.value_len) - Int(BIP32_KEY_FINGERPRINT_LEN))

        var components: [UInt32] = []
        for j in 0..<keyPath.count / 4 {
            let data = keyPath.subdata(in: (j * 4)..<((j + 1) * 4)).withUnsafeBytes{ $0.load(as: UInt32.self) }
            components.append(data)
        }
        let path = DerivationPath(rawPath: components, origin: .fingerprint(fingerprint))!
        result.append(PSBTSigningOrigin(key: pubKey, path: path))
    }
    return result
}

func getSignatures(signatures: wally_map) -> [ECCompressedPublicKey: Data] {
    var result: [ECCompressedPublicKey: Data] = [:]
    for i in 0 ..< signatures.num_items {
        let item = signatures.items[i]
        let pubKey = ECCompressedPublicKey(Data(bytes: item.key, count: Int(EC_PUBLIC_KEY_LEN)))!
        let sig = Data(bytes: item.value, count: Int(item.value_len))
        result[pubKey] = sig
    }
    return result
}

extension PSBTInput {
    public func signingStatus<SignerType: PSBTSigner>(signers: [SignerType]) -> [PSBTSigningStatus<SignerType>] {
        let signatures = Set(signatures.map({ $0.key }))
        return origins.map { $0.signingStatus(seeds: signers, signatures: signatures) }
    }
}
