//
//  BIP39.swift
//  BCFoundation
//

import Foundation
import WolfBase
import SecureComponents

public struct BIP39 {
    public let mnemonic: String
    public let data: Data

    public var words: [String] {
        mnemonic.split(separator: " ").map({ String($0) })
    }

    public init?(mnemonic: String) {
        guard let data = Wally.bip39Decode(mnemonic: mnemonic) else {
            return nil
        }
        self.data = data
        self.mnemonic = mnemonic
    }
    
    public init?(words: [String]) {
        self.init(mnemonic: words.joined(separator: " "))
    }
    
    public init?(data: Data) {
        guard data.count <= 32 else {
            return nil
        }
        self.data = data
        self.mnemonic = Wally.bip39Encode(data: data)
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data: data)
    }

    public static let allWords: [String] = {
        return Wally.bip39AllWords()
    }()
}

extension BIP39: Equatable {
    public static func == (lhs: BIP39, rhs: BIP39) -> Bool {
        lhs.data == rhs.data
    }
}

extension BIP39: CustomStringConvertible {
    public var description: String {
        mnemonic
    }
}

extension BIP39 {
    public struct Seed : Equatable, CustomStringConvertible {
        let data: Data

        public init?(hex: String) {
            guard let data = Data(hex: hex) else {
                return nil
            }
            self.data = data
        }

        init(_ data: Data) {
            self.data = data
        }

        public init(bip39: BIP39, passphrase: String? = nil) {
            self.data = Wally.bip39MnemonicToSeed(mnemonic: bip39.mnemonic, passphrase: passphrase)
        }

        public var description: String {
            data.hex
        }
    }
}
