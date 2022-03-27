//
//  ECKey.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation
@_exported import BCWally
import URKit
import WolfBase

public protocol ECKey {
    static var keyLen: Int { get }

    var data: Data { get }
    
    init?(_ data: Data)
    
    var hex: String { get }
    
    var `public`: ECCompressedPublicKey { get }
    
    var cbor: CBOR { get }
    var taggedCBOR: CBOR { get }
}

extension ECKey {
    public var hex: String {
        data.hex
    }

    public var description: String {
        hex
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.ecKey.tag, cbor)
    }
}

public protocol ECPublicKey: ECKey {
    var compressed: ECCompressedPublicKey { get }
    var uncompressed: ECUncompressedPublicKey { get }
}

public struct ECPrivateKey: ECKey {
    public static let keyLen = Int(EC_PRIVATE_KEY_LEN)
    public let data: Data

    public init?(_ data: Data) {
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var `public`: ECCompressedPublicKey {
        return ECCompressedPublicKey(Wally.ecPublicKeyFromPrivateKey(data: data))!
    }
    
    public var xOnlyPublic: ECXOnlyPublicKey {
        let kp = LibSecP256K1.keyPair(from: self.data)!
        let x = LibSecP256K1.xOnlyPublicKey(from: kp)
        let data = LibSecP256K1.serialize(key: x)
        return ECXOnlyPublicKey(data)!
    }
    
    public func schnorrSign(message: DataProvider, tag: DataProvider) -> Data {
        let kp = LibSecP256K1.keyPair(from: self.data)!
        return LibSecP256K1.schnorrSign(msg: message.providedData, tag: tag.providedData, keyPair: kp)
    }
    
    public var wif: String {
        Wally.encodeWIF(key: data, network: .mainnet, isPublicKeyCompressed: true)
    }

    public var cbor: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#cddl
        CBOR.orderedMap([
            2: .boolean(true),
            3: .data(data)
        ])
    }
}

extension ECPrivateKey: CustomStringConvertible {
}

public struct ECXOnlyPublicKey: Hashable {
    public static var keyLen = 32
    public let data: Data

    public init?(_ data: Data) {
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }
    
    public func schnorrVerify(signature: Data, tag: DataProvider, message: DataProvider) -> Bool {
        let publicKey = LibSecP256K1.xOnlyPublicKey(from: data)!
        return LibSecP256K1.schnorrVerify(msg: message.providedData, tag: tag.providedData, signature: signature, publicKey: publicKey)
    }
}

public struct ECCompressedPublicKey: ECPublicKey, Hashable {
    public static var keyLen: Int = Int(EC_PUBLIC_KEY_LEN)
    public let data: Data

    public init?(_ data: Data) {
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var compressed: ECCompressedPublicKey {
        self
    }
    
    public var uncompressed: ECUncompressedPublicKey {
        return ECUncompressedPublicKey(Wally.ecPublicKeyDecompress(data: data))!
    }
    
    public func address(version: UInt8) -> String {
        var hash = hash160
        hash.insert(version, at: 0)
        return hash.base58(isCheck: true)
    }
    
    public func address(useInfo: UseInfo, isSH: Bool) -> String {
        address(version: isSH ? useInfo.versionSH : useInfo.versionPKH)
    }

    public var `public`: ECCompressedPublicKey {
        self
    }
    
    public var hash160: Data {
        data.hash160
    }

    public var cbor: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#cddl
        CBOR.orderedMap([3: .data(data)])
    }
}

extension ECCompressedPublicKey: CustomStringConvertible {
}

public struct ECUncompressedPublicKey: ECPublicKey {
    public static var keyLen: Int = Int(EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
    public let data: Data

    public init?(_ data: Data) {
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var compressed: ECCompressedPublicKey {
        return ECCompressedPublicKey(Wally.ecPublicKeyCompress(data: data))!
    }
    
    public var uncompressed: ECUncompressedPublicKey {
        self
    }

    public var `public`: ECCompressedPublicKey {
        self.compressed
    }

    public var cbor: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#cddl
        CBOR.orderedMap([3: .data(data)])
    }
}

extension ECUncompressedPublicKey: CustomStringConvertible {
}
