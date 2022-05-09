import XCTest
import BCFoundation
import WolfBase

class SecP256K1Tests: XCTestCase {
    func test1() {
        let scalar1 = Scalar(5)
        let scalar2 = Scalar(10)
        print(scalar1)
        print(scalar2)
        print(scalar1 + scalar2)
        var scalar3 = scalar1
        scalar3 += scalar2
        print(scalar1)
        print(scalar2)
        print(scalar3)
        scalar3 *= Scalar(10)
        print(scalar3)
        let scalar4 = Scalar()
        print(scalar4)
    }
    
    func test2() {
        let scalar1 = Scalar(5)
        let scalar2 = -Scalar(1)
        let scalar3 = scalar1 + scalar2
        var scalar4 = scalar1
        scalar4 -= scalar1
        print(scalar1)
        print(scalar2)
        print(scalar3)
        print(scalar4)
        print(scalar1.isZero)
        print(scalar4.isZero)
    }
    
    func test3() {
        var scalar1 = Scalar(5) - Scalar(4)
        print(scalar1.isOne)
        scalar1 -= Scalar(1)
        print(scalar1.isOne)
    }
    
    func test4() {
        var scalar1 = Scalar(5)
        print(scalar1.isEven)
        scalar1 -= Scalar(1)
        print(scalar1.isEven)
    }
    
    public func test5() {
        print(Scalar(5) == Scalar(5))
        print(Scalar(5) == Scalar(3))
    }
    
//    public func test6() {
//        let sk = SigningPrivateKey()
//        let pk = sk.schnorrPublicKey
//        let t = Scalar()
//    }
}

