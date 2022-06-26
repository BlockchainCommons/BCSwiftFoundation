import XCTest
import BCFoundation
import BCWally
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

    func testMultisig() throws {
//        let account = Account(policy: .init(quorum: 2, slots: 3), network: .testnet)
        
        let aliceSeed = Seed()
        let aliceDescriptorSource = try makeDescriptor(seed: aliceSeed, outputType: .wpkh, accountIndex: 0, network: .testnet)
        print(aliceDescriptorSource)
//        try account.setSource(aliceDescriptorSource, slotIndex: 0)

//        let bobSeed = Seed()
//        let bobDescriptorSource = try makeDescriptor(seed: bobSeed, outputType: .wpkh, accountIndex: 0, network: .testnet)
//        try account.setSource(bobDescriptorSource, slotIndex: 1)
//
//        let fawnSeed = Seed()
//        let fawnDescriptorSource = try makeDescriptor(seed: fawnSeed, outputType: .wpkh, accountIndex: 0, network: .testnet)
//        try account.setSource(fawnDescriptorSource, slotIndex: 2)
//
//        XCTAssert(account.isComplete)
    }
}
