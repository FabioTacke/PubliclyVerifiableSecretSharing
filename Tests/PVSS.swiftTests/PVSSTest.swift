//
//  PVSSTest.swift
//  PVSS.swift
//
//  Created by Fabio Tacke on 28.04.17.
//
//

import XCTest
import BigInt
import CryptoSwift
@testable import PVSS_swift

class PVSSTest: XCTestCase {
  
  var pvssInstance: PVSSInstance!
  var privateKey: BigUInt!
  
  override func setUp() {
    super.setUp()
    
    let q: BigUInt = BigUInt(179426549)
    let g: BigUInt = BigUInt(1301081)
    let G: BigUInt = BigUInt(15486487)
    
    let length: Int = 64
    
    pvssInstance = PVSSInstance(length: length, q: q, g: g, G: G)
    privateKey = BigUInt(105929)
  }
  
  func testPublicKeyGenerator() {
    let publicKey: BigUInt = pvssInstance.generatePublicKey(privateKey: privateKey)
    let checkPublicKey: BigUInt = BigUInt(148446388)
    
    XCTAssertEqual(publicKey, checkPublicKey)
  }
  
  func testDistribution() {
    let distributor = Participant(pvssInstance: pvssInstance, privateKey: privateKey, publicKey: pvssInstance.generatePublicKey(privateKey: privateKey))
    let polynomial = Polynomial(coefficients: [BigUInt(164102006), BigUInt(43489589), BigUInt(98100795)])
    let threshold: Int = 3
    let publicKeys: [BigUInt] = [BigUInt(92086053), BigUInt(132222922), BigUInt(120540987)]
    let w: BigUInt = BigUInt(6345)
    
    let distributionBundle = distributor.distribute(publicKeys: publicKeys, threshold: threshold, polynomial: polynomial, w: w)
    
    // Correct values
    let commitments: [BigUInt] = [BigUInt(92318234), BigUInt(76602245), BigUInt(63484157)]
    let shares: [BigUInt: BigUInt] = [publicKeys[0]: BigUInt(66302038), publicKeys[1]: BigUInt(77501044), publicKeys[2]: BigUInt(92606102)]
    let challenge: BigUInt = BigUInt(95567444)
    let responses: [BigUInt: BigUInt] = [publicKeys[0]: BigUInt(70109777), publicKeys[1]: BigUInt(91929113), publicKeys[2]: BigUInt(13301501)]
    
    // Check calculated values
    XCTAssertEqual(distributionBundle.publicKeys[0], publicKeys[0])
    XCTAssertEqual(distributionBundle.publicKeys[1], publicKeys[1])
    XCTAssertEqual(distributionBundle.publicKeys[2], publicKeys[2])
    
    XCTAssertEqual(distributionBundle.challenge, challenge)
    
    for i in 0...2 {
      XCTAssertEqual(distributionBundle.commitments[i], commitments[i])
      XCTAssertEqual(distributionBundle.shares[publicKeys[i]], shares[publicKeys[i]])
      XCTAssertEqual(distributionBundle.responses[publicKeys[i]], responses[publicKeys[i]])
    }
  }
}
