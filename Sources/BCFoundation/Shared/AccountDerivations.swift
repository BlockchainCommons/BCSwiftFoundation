//
//  AccountDerivations.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation
import WolfBase

public class AccountDerivations {
    public let useInfo: UseInfo
    public let account: UInt32?
    public let seed: Seed?
    
    
    public init(seed: Seed, useInfo: UseInfo, account: UInt32) {
        self.seed = seed
        self.useInfo = useInfo
        self.account = account
    }
    
    public convenience init?(mnemonic: String, useInfo: UseInfo, account: UInt32) {
        guard let bip39 = BIP39(mnemonic: mnemonic) else {
            return nil
        }
        let seed = Seed(bip39: bip39)
        self.init(seed: seed, useInfo: useInfo, account: account)
    }
    
    public init(bip39Seed: BIP39.Seed, useInfo: UseInfo, account: UInt32) {
        self.seed = nil
        self.useInfo = useInfo
        self.account = account
        
        self.bip39Seed = bip39Seed
    }
    
    public init(masterKey: HDKey, useInfo: UseInfo, account: UInt32) {
        self.seed = nil
        self.useInfo = useInfo
        self.account = account
        
        self.accountPath = masterKey.children
        self.masterKey = masterKey
    }
    
    public init(accountKey: HDKey, useInfo: UseInfo) {
        self.seed = nil
        self.useInfo = useInfo
        self.account = nil
        
        self.accountKey = accountKey
    }

    
    public private(set) lazy var accountPath: DerivationPath = {
        return useInfo.accountDerivationPath(account: account!)
    }()
    
    public private(set) lazy var bip39Seed: BIP39.Seed? = {
        guard let bip39 = seed?.bip39 else {
            return nil
        }
        return BIP39.Seed(bip39: bip39)
    }()
    
    public private(set) lazy var masterKey: HDKey? = {
        guard let bip39Seed = bip39Seed else {
            return nil
        }
        return try? HDKey(bip39Seed: bip39Seed)
    }()
    
    public private(set) lazy var accountKey: HDKey? = {
        guard let masterKey = masterKey else {
            return nil
        }
        return try? HDKey(parent: masterKey, childDerivationPath: accountPath)
    }()
    
    public private(set) lazy var accountECPrivateKey: ECPrivateKey? = {
        guard let accountKey = accountKey else {
            return nil
        }
        return accountKey.ecPrivateKey
    }()
    
    public private(set) lazy var accountECPublicKey: (any ECPublicKeyProtocol)? = {
        guard let accountECPrivateKey = accountECPrivateKey else {
            return nil
        }
        return accountECPrivateKey.publicKey
    }()
}
