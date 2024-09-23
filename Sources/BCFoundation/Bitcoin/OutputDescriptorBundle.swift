//
//  OutputDescriptorBundle.swift
//  
//
//  Created by Wolf McNally on 12/5/21.
//

import Foundation
import URKit

// https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-015-account.md

public struct OutputDescriptorBundle: Sendable {
    public let masterKey: any HDKeyProtocol
    public let network: Network
    public let account: UInt32
    public let descriptors: [OutputDescriptor]
    public let descriptorsByOutputType: [AccountOutputType: OutputDescriptor]
    
    public init?(masterKey: any HDKeyProtocol, network: Network, account: UInt32, outputTypes: [AccountOutputType] = AccountOutputType.bundleCases) {
        guard
            masterKey.isMaster,
            !outputTypes.isEmpty,
            let descriptors: [OutputDescriptor] = try? outputTypes.map( {
                let a = try $0.accountDescriptor(masterKey: masterKey, network: network, account: account, includeAddressDerivationPath: false)
                return a;
            })
        else {
            return nil
        }
        var descriptorsByOutputType: [AccountOutputType: OutputDescriptor] = [:]
        zip(outputTypes, descriptors).forEach {
            descriptorsByOutputType[$0] = $1
        }
        self.masterKey = masterKey
        self.network = network
        self.account = account
        self.descriptors = descriptors
        self.descriptorsByOutputType = descriptorsByOutputType
    }
}

extension OutputDescriptorBundle: UREncodable {
    public static let cborTags = [Tag.accountDescriptor, Tag.accountV1]

    public var untaggedCBOR: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-015-account.md#cddl
        CBOR.map([
            1: masterKey.keyFingerprint,
            2: descriptors.map { $0.taggedCBOR }
        ])
    }
}
