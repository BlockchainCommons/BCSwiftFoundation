import Foundation
import secp256k1
import WolfBase

enum LibSecP256K1 {
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
                        _ = secp256k1_schnorrsig_sign(context, sig64.baseAddress!, msg32.baseAddress!, keyPair, auxRand.baseAddress)
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
    
    static func schnorrVerify(msg: Data, tag: Data, signature: Data, publicKey: secp256k1_xonly_pubkey) -> Bool {
        precondition(signature.count == 64)
        
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))!
        defer { secp256k1_context_destroy(context) }

        let digestCount = 32
        let digest = taggedSHA256(msg: msg, tag: tag)
        
        let result: Int32 = signature.withUnsafeByteBuffer { signature in
            digest.withUnsafeByteBuffer { digest in
                withUnsafePointer(to: publicKey) { publicKey in
                    secp256k1_schnorrsig_verify(context, signature.baseAddress!, digest.baseAddress!, digestCount, publicKey)
                }
            }
        }
        return result == 1
    }
}
