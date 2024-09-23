//
//  AccountDerivations.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation
import WolfBase

public final class AccountDerivations: @unchecked Sendable {
    
    private final class Cache {
        var accountPath: DerivationPath? = nil
        var bip39Seed: BIP39.Seed? = nil
        var masterKey: HDKey? = nil
        var accountKey: HDKey? = nil
        var accountECPrivateKey: ECPrivateKey? = nil
        var accountECDSAPublicKey: (any SecP256K1PublicKeyProtocol)? = nil
        var accountEd25519PublicKey: Ed25519PublicKey? = nil
        
        init() {
        }
    }
    
    private let lock = NSRecursiveLock()
    private let cache = Cache()

    public let useInfo: UseInfo
    public let account: UInt32?
    public let seed: Seed?

    private func withCache<T>(_ body: (Cache) throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try body(cache)
    }

    
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
        
        withCache { cache in
            cache.bip39Seed = bip39Seed
        }
    }
    
    public init(masterKey: HDKey, useInfo: UseInfo, account: UInt32) {
        self.seed = nil
        self.useInfo = useInfo
        self.account = account
        
        withCache { cache in
            cache.accountPath = masterKey.children
            cache.masterKey = masterKey
        }
    }
    
    public init(accountKey: HDKey, useInfo: UseInfo) {
        self.seed = nil
        self.useInfo = useInfo
        self.account = nil
        
        withCache { cache in
            cache.accountKey = accountKey
        }
    }

    public var accountPath: DerivationPath {
        withCache { cache in
            if cache.accountPath == nil {
                cache.accountPath = useInfo.accountDerivationPath(account: account!)
            }
            return cache.accountPath!
        }
    }
    
    public var bip39Seed: BIP39.Seed? {
        withCache { cache in
            if cache.bip39Seed == nil {
                if let bip39 = seed?.bip39 {
                    cache.bip39Seed = BIP39.Seed(bip39: bip39)
                }
            }
            return cache.bip39Seed
        }
    }

    public var masterKey: HDKey? {
        withCache { cache in
            if cache.masterKey == nil {
                if let bip39Seed = bip39Seed {
                    cache.masterKey = try? HDKey(bip39Seed: bip39Seed)
                }
            }
            return cache.masterKey
        }
    }
    
    public var accountKey: HDKey? {
        withCache { cache in
            if cache.accountKey == nil {
                if let masterKey = masterKey {
                    cache.accountKey = try? HDKey(parent: masterKey, childDerivationPath: accountPath)
                }
            }
            return cache.accountKey
        }
    }
    
    public var accountECPrivateKey: ECPrivateKey? {
        withCache { cache in
            if cache.accountECPrivateKey == nil {
                if let accountKey = accountKey {
                    cache.accountECPrivateKey = accountKey.ecPrivateKey
                }
            }
            return cache.accountECPrivateKey
        }
    }
    
    public var accountECDSAPublicKey: (any SecP256K1PublicKeyProtocol)? {
        withCache { cache in
            if cache.accountECDSAPublicKey == nil {
                if let accountECPrivateKey = accountECPrivateKey {
                    cache.accountECDSAPublicKey = accountECPrivateKey.secp256k1PublicKey
                }
            }
            return cache.accountECDSAPublicKey
        }
    }
    
    public var accountEd25519PublicKey: Ed25519PublicKey? {
        withCache { cache in
            if cache.accountEd25519PublicKey == nil {
                if let accountECPrivateKey = accountECPrivateKey {
                    cache.accountEd25519PublicKey = accountECPrivateKey.ed25519PublicKey
                }
            }
            return cache.accountEd25519PublicKey
        }
    }
}
