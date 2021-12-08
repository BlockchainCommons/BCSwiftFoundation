//
//  AccountOutputType.swift
//  
//
//  Created by Wolf McNally on 12/7/21.
//

import Foundation
import WolfBase

public enum AccountOutputType: CaseIterable, Identifiable {
    case pkh
    case shwpkh
    case wpkh
    case shcosigner
    case shwshcosigner
    case wshcosigner
    case trsingle
    
    public var id: String {
        return self†
    }
    
    public func descriptorSource(accountKey: HDKeyProtocol) -> String {
        let keyExpression = accountKey.description(withParent: true)
        return descriptorSource(keyExpression: keyExpression)
    }
    
    public func descriptorSource(keyExpression: String) -> String {
        switch self {
        case .pkh:
            return "pkh(\(keyExpression))"
        case .shwpkh:
            return "sh(wpkh(\(keyExpression)))"
        case .wpkh:
            return "wpkh(\(keyExpression))"
        case .shcosigner:
            return "sh(cosigner(\(keyExpression)))"
        case .shwshcosigner:
            return "sh(wsh(cosigner(\(keyExpression))))"
        case .wshcosigner:
            return "wsh(cosigner(\(keyExpression)))"
        case .trsingle:
            return "tr(\(keyExpression))"
        }
    }

    public func accountDerivationPath(network: Network, account: UInt32) -> DerivationPath {
        let coinType = UseInfo(network: network).coinType
        switch self {
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
    
    public func accountDescriptor(masterKey: HDKeyProtocol, network: Network, account: UInt32) throws -> Descriptor {
        let accountKey = try accountPublicKey(masterKey: masterKey, network: network, account: account)
        let source = descriptorSource(accountKey: accountKey)
        return try Descriptor(source)
    }
    
    public func accountPublicKey(masterKey: HDKeyProtocol, network: Network, account: UInt32) throws -> HDKey {
        let path = accountDerivationPath(network: network, account: account)
        return try HDKey(parent: masterKey, derivedKeyType: .public, childDerivationPath: path)
    }
}
