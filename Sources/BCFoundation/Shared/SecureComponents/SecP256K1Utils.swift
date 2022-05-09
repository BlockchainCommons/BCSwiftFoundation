//
//  File.swift
//  
//
//  Created by Wolf McNally on 4/28/22.
//

import Foundation
import secp256k1
import WolfBase

/// Data concatenation for cryptographic constructions
public func ||(lhs: Data, rhs: Data) -> Data {
    lhs + rhs
}

/// A scalar modulo the group order of the secp256k1 curve.
public struct Scalar {
    private var rep: Rep
    
    private init(_ rep: secp256k1_scalar) {
        self.rep = Rep(rep)
    }
    
    /// Initialize the scalar from the 32-byte `Data`.
    ///
    /// Fails if the `Data` is not exactly 32 bytes.
    ///
    /// The scalar will be reduced modulo group order `n`.
    public init?(_ data: Data) {
        guard data.count == 32 else {
            return nil
        }
        var rep = secp256k1_scalar()
        data.withUnsafeByteBuffer { data in
            secp256k1_scalar_set_b32(&rep, data.baseAddress!, nil)
        }
        self.init(rep)
    }
    
    /// Initialize the scalar to an unsigned integer
    public init(_ i: UInt64) {
        var rep = secp256k1_scalar()
        secp256k1_scalar_set_u64(&rep, i)
        self.init(rep)
    }
    
    /// Initialize the scalar to a random value.
    public init() {
        self.init(SecureRandomNumberGenerator.shared.data(count: 32))!
    }
    
    /// The big endian byte array value of the Scalar
    public var data: Data {
        withUnsafeTemporaryAllocation(byteCount: 32, alignment: 2) { p in
            secp256k1_scalar_get_b32(p.baseAddress!, &rep.value)
            return Data(p)
        }
    }
    
    /// Add two scalars together (modulo the group order). Also returns whether it overflowed.
    public static func add(_ a: Scalar, _ b: Scalar) -> (Scalar, Bool) {
        var result = secp256k1_scalar()
        let didOverflow = secp256k1_scalar_add(&result, &a.rep.value, &b.rep.value) != 0
        return (Scalar(result), didOverflow)
    }
    
    /// Multiply two scalars (modulo the group order).
    public static func mul(_ a: Scalar, _ b: Scalar) -> Scalar {
        var result = secp256k1_scalar()
        secp256k1_scalar_mul(&result, &a.rep.value, &b.rep.value)
        return Scalar(result)
    }
    
    /// Compute the complement of a scalar (modulo the group order).
    public static func negate(_ a: Scalar) -> Scalar {
        var result = secp256k1_scalar()
        secp256k1_scalar_negate(&result, &a.rep.value)
        return Scalar(result)
    }
    
    /// Compare two scalars.
    public static func isEqual(_ a: Scalar, _ b: Scalar) -> Bool {
        secp256k1_scalar_eq(&a.rep.value, &b.rep.value) == 1
    }
    
    /// Check whether a scalar equals zero.
    public var isZero: Bool {
        secp256k1_scalar_is_zero(&rep.value) == 1
    }
    
    /// Check whether a scalar equals one.
    public var isOne: Bool {
        secp256k1_scalar_is_one(&rep.value) == 1
    }
    
    /// Check whether a scalar, considered as an nonnegative integer, is even.
    public var isEven: Bool {
        secp256k1_scalar_is_even(&rep.value) == 1
    }

    private final class Rep {
        var value: secp256k1_scalar
        
        init(_ rep: secp256k1_scalar) {
            self.value = rep
        }
        
        deinit {
            secp256k1_scalar_clear(&value)
        }
    }
}

extension Scalar {
    public static func +(lhs: Scalar, rhs: Scalar) -> Scalar {
        add(lhs, rhs).0
    }
    
    public static func +=(lhs: inout Scalar, rhs: Scalar) {
        if(!isKnownUniquelyReferenced(&lhs.rep)) {
            lhs.rep = Rep(lhs.rep.value)
        }
        lhs = lhs + rhs
    }
    
    public static func *(lhs: Scalar, rhs: Scalar) -> Scalar {
        mul(lhs, rhs)
    }
    
    public static func *=(lhs: inout Scalar, rhs: Scalar) {
        if(!isKnownUniquelyReferenced(&lhs.rep)) {
            lhs.rep = Rep(lhs.rep.value)
        }
        lhs = lhs * rhs
    }
    
    public static prefix func -(rhs: Scalar) -> Scalar {
        negate(rhs)
    }
    
    public static func -(lhs: Scalar, rhs: Scalar) -> Scalar {
        lhs + (-rhs)
    }
    
    public static func -=(lhs: inout Scalar, rhs: Scalar) {
        lhs = lhs - rhs
    }
}

extension Scalar: Equatable {
    public static func ==(lhs: Scalar, rhs: Scalar) -> Bool {
        isEqual(lhs, rhs)
    }
}

extension Scalar: CustomStringConvertible {
    public var description: String {
        data.hex.flanked("Scalar(", ")")
    }
}

