import Foundation
import secp256k1
import WolfBase

enum LibSecP256K1 {
}

extension LibSecP256K1 {
    static func keyPair(from secretKey: Data) -> secp256k1_keypair? {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(context) }
        
        var keypair = secp256k1_keypair()
        let result: Int32 = secretKey.withUnsafeByteBuffer { secretKey in
            return secp256k1_keypair_create(context, &keypair, secretKey.baseAddress!)
        }
        guard result == 1 else {
            return nil
        }
        return keypair
    }
}

extension LibSecP256K1 {
    static func ecPublicKey(from serialized: Data) -> secp256k1_pubkey? {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }

        var pubKey = secp256k1_pubkey()
        let serializedCount = serialized.count
        let result: Int32 = serialized.withUnsafeByteBuffer { serialized in
            secp256k1_ec_pubkey_parse(context, &pubKey, serialized.baseAddress!, serializedCount)
        }
        guard result == 1 else {
            return nil
        }
        return pubKey
    }
    
    static func serialize(key: secp256k1_pubkey) -> Data {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }
        
        var serialized_count = 33
        var serialized = Data(repeating: 0, count: serialized_count)

        serialized.withUnsafeMutableByteBuffer { serialized in
            withUnsafePointer(to: key) { key in
                _ = secp256k1_ec_pubkey_serialize(context, serialized.baseAddress!, &serialized_count, key, UInt32(SECP256K1_EC_COMPRESSED))
            }
        }
        return serialized
    }
    
    static func publicKey(from keyPair: secp256k1_keypair) -> secp256k1_pubkey {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }

        var pubKey = secp256k1_pubkey()
        withUnsafePointer(to: keyPair) { keyPair in
            _ = secp256k1_keypair_pub(context, &pubKey, keyPair);
        }
        return pubKey
    }
    
    static func doubleSHA256(message: Data) -> Data {
        message.sha256().sha256()
    }
    
    static func ecdsaSign32(msg32: Data, secKey: Data) -> Data {
        let msgCount = 32
        precondition(msg32.count == msgCount)
        
        let keyCount = 32
        precondition(secKey.count == keyCount)
        
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(context) }
        
        var sig = secp256k1_ecdsa_signature()
        
        let result = msg32.withUnsafeByteBuffer { msg32 in
            secKey.withUnsafeByteBuffer { seckey in
                secp256k1_ecdsa_sign(context, &sig, msg32.baseAddress!, seckey.baseAddress!, nil, nil)
            }
        }
        precondition(result == 1)
        
        return Data(of: sig)
    }
    
    static func ecdsaSign(message: Data, secKey: Data) -> Data {
        ecdsaSign32(msg32: doubleSHA256(message: message), secKey: secKey)
    }
    
    static func ecdsaVerify32(msg32: Data, signature: Data, publicKey: secp256k1_pubkey) -> Bool {
        precondition(signature.count == 64)
        
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))!
        defer { secp256k1_context_destroy(context) }

        let result = msg32.withUnsafeByteBuffer { msg32 in
            signature.withUnsafeBytes { signature in
                withUnsafePointer(to: publicKey) { publicKey in
                    secp256k1_ecdsa_verify(context, signature.bindMemory(to: secp256k1_ecdsa_signature.self).baseAddress!, msg32.baseAddress!, publicKey)
                }
            }
        }
        return result == 1
    }
    
    static func ecdsaVerify(message: Data, signature: Data, publicKey: secp256k1_pubkey) -> Bool {
        ecdsaVerify32(msg32: doubleSHA256(message: message), signature: signature, publicKey: publicKey)
    }
}

extension LibSecP256K1 {
    static func xOnlyPublicKey(from serialized: Data) -> secp256k1_xonly_pubkey? {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }
        
        var pubKey = secp256k1_xonly_pubkey()
        let result: Int32 = serialized.withUnsafeByteBuffer { serialized in
            return secp256k1_xonly_pubkey_parse(context, &pubKey, serialized.baseAddress!)
        }
        guard result == 1 else {
            return nil
        }
        return pubKey
    }
    
    static func serialize(key: secp256k1_xonly_pubkey) -> Data {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }
        
        var serialized = Data(repeating: 0, count: 32)
        serialized.withUnsafeMutableByteBuffer { serialized in
            withUnsafePointer(to: key) { key in
                _ = secp256k1_xonly_pubkey_serialize(context, serialized.baseAddress!, key)
            }
        }
        return serialized
    }
    
    static func xOnlyPublicKey(from keyPair: secp256k1_keypair) -> secp256k1_xonly_pubkey {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }

        var pubKey = secp256k1_xonly_pubkey()
        withUnsafePointer(to: keyPair) { keyPair in
            _ = secp256k1_keypair_xonly_pub(context, &pubKey, nil, keyPair);
        }
        return pubKey
    }
    
    /// Compute a tagged hash as defined in BIP-340.
    ///
    /// SHA256(SHA256(tag)||SHA256(tag)||msg)
    static func taggedSHA256(msg: Data, tag: Data) -> Data {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }

        let hashCount = 32
        var hash = Data(repeating: 0, count: hashCount)
        let tagCount = tag.count
        let msgCount = msg.count
        
        hash.withUnsafeMutableByteBuffer { hash in
            tag.withUnsafeByteBuffer { tag in
                msg.withUnsafeByteBuffer { msg in
                    _ = secp256k1_tagged_sha256(context, hash.baseAddress!, tag.baseAddress!, tagCount, msg.baseAddress!, msgCount)
                }
            }
        }
        
        return hash
    }
    
    static func schnorrSign32(msg32: Data, keyPair: secp256k1_keypair) -> Data {
        let msgCount = 32
        precondition(msg32.count == msgCount)
        
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(context) }

        let randomizeCount = 32
        let randomize = SecureRandomNumberGenerator.shared.data(count: randomizeCount)
        randomize.withUnsafeByteBuffer {
            _ = secp256k1_context_randomize(context, $0.baseAddress!)
        }

        let sigCount = 64
        var sig64 = Data(repeating: 0, count: sigCount)
        
        let auxRandCount = 32
        let auxRand = SecureRandomNumberGenerator.shared.data(count: auxRandCount)

        sig64.withUnsafeMutableByteBuffer { sig64 in
            msg32.withUnsafeByteBuffer { msg32 in
                withUnsafePointer(to: keyPair) { keyPair in
                    auxRand.withUnsafeByteBuffer { auxRand in
                        _ = secp256k1_schnorrsig_sign32(context, sig64.baseAddress!, msg32.baseAddress!, keyPair, auxRand.baseAddress)
                    }
                }
            }
        }
            
        return sig64
    }
    
    static func schnorrSign(msg: Data, tag: Data, keyPair: secp256k1_keypair) -> Data {
        let digest = taggedSHA256(msg: msg, tag: tag)
        return schnorrSign32(msg32: digest, keyPair: keyPair)
    }
    
    static func schnorrVerify32(msg32: Data, signature: Data, publicKey: secp256k1_xonly_pubkey) -> Bool {
        let msg32Count = 32
        precondition(msg32.count == msg32Count)

        precondition(signature.count == 64)
        
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))!
        defer { secp256k1_context_destroy(context) }

        let result: Int32 = signature.withUnsafeByteBuffer { signature in
            msg32.withUnsafeByteBuffer { msg32 in
                withUnsafePointer(to: publicKey) { publicKey in
                    secp256k1_schnorrsig_verify(context, signature.baseAddress!, msg32.baseAddress!, msg32Count, publicKey)
                }
            }
        }
        return result == 1
    }
    
    static func schnorrVerify(msg: Data, tag: Data, signature: Data, publicKey: secp256k1_xonly_pubkey) -> Bool {
        let msg32 = taggedSHA256(msg: msg, tag: tag)
        return schnorrVerify32(msg32: msg32, signature: signature, publicKey: publicKey)
    }
}
