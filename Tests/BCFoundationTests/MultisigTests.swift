import XCTest
import BCFoundation
import WolfBase

// https://en.bitcoin.it/wiki/Multi-signature#Creating_a_multi-signature_address_with_Bitcoin-Qt
// https://gist.github.com/gavinandresen/3966071

fileprivate struct Policy {
    let quorum: Int
    let slots: Int
}

fileprivate enum TestError: Error {
    case descriptorNotDerivable
}

fileprivate class Slot {
    var descriptor: OutputDescriptor?
    
    init() { }
    
    var isComplete: Bool {
        descriptor != nil
    }
    
    func setSource(_ source: String) throws {
        let descriptor = try OutputDescriptor(source)
        guard descriptor.requiresAddressIndex else {
            throw TestError.descriptorNotDerivable
        }
        self.descriptor = descriptor
    }
}

fileprivate class Account {
    let policy: Policy
    let network: Network
    let slots: [Slot]
    
    init(policy: Policy, network: Network) {
        self.policy = policy
        self.network = network
        self.slots = (0..<policy.slots).map { _ in Slot() }
    }
    
    func setSource(_ source: String, slotIndex: Int) throws {
        try self.slots[slotIndex].setSource(source)
    }
    
    var isComplete: Bool {
        slots.allSatisfy { $0.isComplete }
    }
}

final class MultisigTests: XCTestCase {
    func makeDescriptor(seed: Seed, outputType: AccountOutputType, accountIndex: Int, network: Network) throws -> String {
        let masterKey = try HDKey(seed: seed, useInfo: UseInfo(network: network))
        let descriptor = try outputType.accountDescriptor(masterKey: masterKey, network: network, account: UInt32(accountIndex))
        return descriptor.source
    }

//    Alice:
//    wpkh([55016b2f/84h/1h/0h]tpubDC8LiEDg3kCFJgZHhBSs6gY8WtpR1K3Y9rP3beDnR14tM5waXvgjYveW1Dmi6kr2LVdj8nPCu5myATRydoRFN2hGSwZ518rRg7KJirdAWmg/<0;1>/*)#w44vzfr8
//
//    Bob:
//    wpkh([a7e8d06e/84h/1h/0h]tpubDCGrpJ7dTCwZJhsCy7jbXihZdx627sGBs32KUiSnVEghWak8GA6wVM1f4WEofTZBtMnKfRSwzTxYsJQ5DaBnt2G5dfHuX9saTSytUwVQKfE/<0;1>/*)#5zfxcrqr
//
//    Fawn:
//    wpkh([f5d5473b/84h/1h/0h]tpubDDmMe9yuB5BWZXNmCDx9ByxrtasfgRLuVXhbD154dBGFBYGVCbC9MtLvMGZXfaG8WwFpZGNMrRWm8sHGuMsanh9ceFQJ5PDKH9rGJZbA1cs/<0;1>/*)#5kmtc5es

    func testMultisig() throws {
        let aliceSource = "wpkh([55016b2f/84h/1h/0h]tpubDC8LiEDg3kCFJgZHhBSs6gY8WtpR1K3Y9rP3beDnR14tM5waXvgjYveW1Dmi6kr2LVdj8nPCu5myATRydoRFN2hGSwZ518rRg7KJirdAWmg/<0;1>/*)#w44vzfr8"
        let aliceDesc = try OutputDescriptor(aliceSource)
        print(aliceDesc)
        let indexRange: Range<UInt32> = 0..<20
        let addresses = aliceDesc.addresses(useInfo: UseInfo(network: .testnet), chain: .external, indexes: indexRange)
        for index in indexRange {
            print("\(index): \(addresses[index]!)")
        }
    }
}
