//
//  KeyRequestBody.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import URKit
import WolfBase
import Envelope

public struct KeyRequestBody: TransactionRequestBody {
    public static var function = Function.getKey
    public let keyType: KeyType
    public let path: DerivationPath
    public let useInfo: UseInfo
    public let isDerivable: Bool

    public init(keyType: KeyType, path: DerivationPath, useInfo: UseInfo, isDerivable: Bool = true) {
        self.keyType = keyType
        self.path = path
        self.useInfo = useInfo
        self.isDerivable = isDerivable
    }
}

public extension KeyRequestBody {
    var envelope: Envelope {
        try! Envelope(function: .getKey)
            .addAssertion(.parameter(.derivationPath, value: path))
            .addAssertion(if: !keyType.isPrivate, .parameter(.isPrivate, value: false))
            .addAssertion(if: !useInfo.isDefault, .parameter(.useInfo, value: useInfo))
            .addAssertion(if: !isDerivable, .parameter(.isDerivable, value: false))
    }
    
    init(_ envelope: Envelope) throws {
        let path = try envelope.extractObject(DerivationPath.self, forParameter: .derivationPath)

        let isPrivate = (try? envelope.extractObject(Bool.self, forParameter: .isPrivate)) ?? true
        let keyType = KeyType(isPrivate: isPrivate)
        
        let useInfo = (try? envelope.extractObject(UseInfo.self, forParameter: .useInfo)) ?? UseInfo()
        
        let isDerivable = (try? envelope.extractObject(Bool.self, forParameter: .isDerivable)) ?? true
        
        self.init(keyType: keyType, path: path, useInfo: useInfo, isDerivable: isDerivable)
    }
}
