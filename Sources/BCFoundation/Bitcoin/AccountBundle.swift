//
//  AccountBundle.swift
//  
//
//  Created by Wolf McNally on 12/5/21.
//

import Foundation
@_exported import URKit

// https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-015-account.md

public struct AccountBundle {
    public let masterKey: HDKeyProtocol
    public let network: Network
    public let account: UInt32
    public let descriptors: [Descriptor]
    public let descriptorsByOutputType: [OutputType: Descriptor]
    
    public enum OutputType: CaseIterable {
        case pkh
        case shwpkh
        case wpkh
        case shcosigner
        case shwshcosigner
        case wshcosigner
        case trsingle
    }
    
    public init?(masterKey: HDKeyProtocol, network: Network, account: UInt32, outputTypes: [OutputType] = OutputType.allCases) {
        guard
            masterKey.isMaster,
            !outputTypes.isEmpty,
            let descriptors: [Descriptor] = try? outputTypes.map( {
                let a = try Self.accountDescriptor(masterKey: masterKey, outputType: $0, network: network, account: account)
                return a;
            })
        else {
            return nil
        }
        var descriptorsByOutputType: [OutputType: Descriptor] = [:]
        zip(outputTypes, descriptors).forEach {
            descriptorsByOutputType[$0] = $1
        }
        self.masterKey = masterKey
        self.network = network
        self.account = account
        self.descriptors = descriptors
        self.descriptorsByOutputType = descriptorsByOutputType
    }
    
    static func accountDescriptor(masterKey: HDKeyProtocol, outputType: OutputType, network: Network, account: UInt32) throws -> Descriptor {
        let accountKey = try accountPublicKey(masterKey: masterKey, outputType: outputType, network: network, account: account)
        let source = descriptorSource(outputType: outputType, accountKey: accountKey)
        return try Descriptor(source)
    }
    
    static func accountPublicKey(masterKey: HDKeyProtocol, outputType: OutputType, network: Network, account: UInt32) throws -> HDKey {
        let path = accountDerivationPath(outputType: outputType, network: network, account: account)
        return try HDKey(parent: masterKey, derivedKeyType: .public, childDerivationPath: path)
    }
    
    static func descriptorSource(outputType: OutputType, accountKey: HDKeyProtocol) -> String {
        let key = accountKey.description(withParent: true)
        switch outputType {
        case .pkh:
            return "pkh(\(key))"
        case .shwpkh:
            return "sh(wpkh(\(key)))"
        case .wpkh:
            return "wpkh(\(key))"
        case .shcosigner:
            return "sh(cosigner(\(key)))"
        case .shwshcosigner:
            return "sh(wsh(cosigner(\(key))))"
        case .wshcosigner:
            return "wsh(cosigner(\(key)))"
        case .trsingle:
            return "tr(\(key))"
        }
    }

    static func accountDerivationPath(outputType: OutputType, network: Network, account: UInt32) -> DerivationPath {
        let coinType = UseInfo(network: network).coinType
        switch outputType {
        case .pkh:
            return .init(string: "44'/\(coinType)'/\(account)'")!
        case .shwpkh:
            return .init(string: "49'/\(coinType)'/\(account)'")!
        case .wpkh:
            return .init(string: "84'/\(coinType)'/\(account)'")!
        case .shcosigner:
            return .init(string: "45'")!
        case .shwshcosigner:
            return .init(string: "48'/\(coinType)'/\(account)'/1'")!
        case .wshcosigner:
            return .init(string: "48'/\(coinType)'/\(account)'/2'")!
        case .trsingle:
            return .init(string: "86'/\(coinType)'/\(account)'")!
        }
    }
    
    public var cbor: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-015-account.md#cddl
        CBOR.orderedMap([
            .init(key: 1, value: .unsignedInt(UInt64(masterKey.keyFingerprint))),
            .init(key: 2, value: .array(descriptors.map({$0.taggedCBOR})))
        ])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.account.tag, cbor)
    }
    
    public var ur: UR {
        try! UR(type: URType.account.type, cbor: cbor)
    }
}
