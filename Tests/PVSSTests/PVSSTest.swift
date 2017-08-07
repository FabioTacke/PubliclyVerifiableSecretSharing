//
//  PVSSTest.swift
//  PVSS
//
//  Created by Fabio Tacke on 28.04.17.
//
//

import XCTest
import BigInt
import Bignum
import CryptoSwift
@testable import PVSS

class PVSSTest: XCTestCase {
  
  var pvssInstance: PVSSInstance!
  var privateKey: Bignum!
  var secret: Bignum!
  
  override func setUp() {
    super.setUp()
    
    let q: Bignum = Bignum(179426549)
    let g: Bignum = Bignum(1301081)
    let G: Bignum = Bignum(15486487)
    
    let length: Int = 64
    
    pvssInstance = PVSSInstance(length: length, q: q, g: g, G: G)
    privateKey = Bignum(105929)
    secret = Bignum(1234567890)
  }
  
  func testPublicKeyGenerator() {
    let publicKey: Bignum = pvssInstance.generatePublicKey(privateKey: privateKey)
    let checkPublicKey: Bignum = Bignum(148446388)
    
    XCTAssertEqual(publicKey, checkPublicKey)
  }
  
  func testGeneratingPVSSParameters() {
    let pvss = PVSSInstance(length: 32)
    
    XCTAssert(BigUInt((pvss.q).description)!.isPrime())
    XCTAssert(BigUInt((pvss.g).description)!.isPrime())
    XCTAssertEqual(pvss.g, Bignum((BigUInt((pvss.q-1).description)!.divided(by: 2).quotient).description))
  }
  
  func testDistribution() {
    let distributionBundle = getDistributionBundle()
    
    // Correct values
    let commitments: [Bignum] = [Bignum(92318234), Bignum(76602245), Bignum(63484157)]
    let shares: [Bignum: Bignum] = [distributionBundle.publicKeys[0]: Bignum(42478042), distributionBundle.publicKeys[1]: Bignum(80117658), distributionBundle.publicKeys[2]: Bignum(86941725)]
    let challenge: Bignum = Bignum(41963410)
    let responses: [Bignum: Bignum] = [distributionBundle.publicKeys[0]: Bignum(151565889), distributionBundle.publicKeys[1]: Bignum(146145105), distributionBundle.publicKeys[2]: Bignum(71350321)]
    
    // Check calculated values
    XCTAssertEqual(distributionBundle.publicKeys[0], distributionBundle.publicKeys[0])
    XCTAssertEqual(distributionBundle.publicKeys[1], distributionBundle.publicKeys[1])
    XCTAssertEqual(distributionBundle.publicKeys[2], distributionBundle.publicKeys[2])
    
    XCTAssertEqual(distributionBundle.challenge, challenge)
    
    for i in 0...2 {
      XCTAssertEqual(distributionBundle.commitments[i], commitments[i])
      XCTAssertEqual(distributionBundle.shares[distributionBundle.publicKeys[i]], shares[distributionBundle.publicKeys[i]])
      XCTAssertEqual(distributionBundle.responses[distributionBundle.publicKeys[i]], responses[distributionBundle.publicKeys[i]])
    }
  }
  
  func testDistributionBundleVerification() {
    let distributionBundle = getDistributionBundle()
    
    XCTAssert(pvssInstance.verify(distributionBundle: distributionBundle))
  }
  
  func testShareExtraction() {
    let shareBundle = getShareBundle()
    
    XCTAssertEqual(shareBundle.share, Bignum(164021044))
    XCTAssertEqual(shareBundle.challenge, Bignum(134883166))
    XCTAssertEqual(shareBundle.response, Bignum(81801891))
  }
  
  func testShareBundleVerification() {
    let privateKey = Bignum(7901)
    let distributionBundle = getDistributionBundle()
    let shareBundle = getShareBundle()
    
    XCTAssert(pvssInstance.verify(shareBundle: shareBundle, encryptedShare: distributionBundle.shares[pvssInstance.generatePublicKey(privateKey: privateKey)]!))
  }
  
  func testReconstructionWithAllParticipants() {
    let distributionBundle = getDistributionBundle()
    let shareBundle1 = getShareBundle()
    let shareBundle2 = ShareBundle(publicKey: Bignum(132222922), share: Bignum(157312059), challenge: Bignum(0), response: Bignum(0))
    let shareBundle3 = ShareBundle(publicKey: Bignum(65136827), share: Bignum(63399333), challenge: Bignum(0), response: Bignum(0))
    
    let shareBundles = [shareBundle1, shareBundle2, shareBundle3]

    // All the shares are present
    guard let reconstructedSecret = pvssInstance.reconstruct(shareBundles: shareBundles, distributionBundle: distributionBundle) else {
      XCTFail()
      return
    }

    XCTAssertEqual(reconstructedSecret, secret)
  }
  
  // 3 out of 4 shares are present. Share of P3 is not available, therefore we need another Share of P_4 in order to reconstruct the secret.
  func testReconstructionWithSubgroup() {
    let shareBundle1 = getShareBundle()
    let shareBundle2 = ShareBundle(publicKey: Bignum(132222922), share: Bignum(157312059), challenge: Bignum(0), response: Bignum(0))
    let publicKey4 = Bignum(42)
    let shareBundle4 = ShareBundle(publicKey: publicKey4, share: Bignum(59066181), challenge: Bignum(0), response: Bignum(0))
    
    var positions = [shareBundle1.publicKey: 1, shareBundle2.publicKey: 2, shareBundle4.publicKey: 4]
    positions.removeValue(forKey: Bignum(65136827))
    positions[publicKey4] = 4
    let distributionBundle = DistributionBundle(commitments: [0, 1, 2], positions: positions, shares: [:], publicKeys: [], challenge: Bignum(0), responses: [:], U: Bignum(1284073502))
    let shareBundles = [shareBundle1, shareBundle2, shareBundle4]
    
    guard let reconstructedSecret = pvssInstance.reconstruct(shareBundles: shareBundles, distributionBundle: distributionBundle) else {
      XCTFail()
      return
    }
    
    XCTAssertEqual(reconstructedSecret, secret)
    
  }
  
  func testExample() {
    let secretMessage = "Correct horse battery staple."
    let secret = Bignum(data: secretMessage.data(using: .utf8)!)
    
    // Create default PVSS Instance for the dealer
    let pvssInstance = PVSSInstance(length: 128)
    let dealer = Participant(pvssInstance: pvssInstance)
    
    // Participants p1, p2 and p3
    let p1 = Participant(pvssInstance: dealer.pvssInstance)
    let p2 = Participant(pvssInstance: dealer.pvssInstance)
    let p3 = Participant(pvssInstance: dealer.pvssInstance)
    
    // Dealer that shares the secret among p1, p2 and p3
    let distributionBundle = dealer.distribute(secret: secret, publicKeys: [p1.publicKey, p2.publicKey, p3.publicKey], threshold: 3)
    
    // Receivers verify distribution bundle
    XCTAssert(p1.pvssInstance.verify(distributionBundle: distributionBundle))
    XCTAssert(p2.pvssInstance.verify(distributionBundle: distributionBundle))
    XCTAssert(p3.pvssInstance.verify(distributionBundle: distributionBundle))
    
    // Receivers extract (and submit) their shares
    guard let s1 = p1.extractShare(distributionBundle: distributionBundle, privateKey: p1.privateKey),
      let s2 = p2.extractShare(distributionBundle: distributionBundle, privateKey: p2.privateKey),
      let s3 = p3.extractShare(distributionBundle: distributionBundle, privateKey: p3.privateKey) else {
        XCTFail()
        return
    }
    
    // Receivers verify the shares
    XCTAssert(p1.pvssInstance.verify(shareBundle: s2, distributionBundle: distributionBundle, publicKey: p2.publicKey))
    XCTAssert(p1.pvssInstance.verify(shareBundle: s3, distributionBundle: distributionBundle, publicKey: p3.publicKey))
    XCTAssert(p2.pvssInstance.verify(shareBundle: s1, distributionBundle: distributionBundle, publicKey: p1.publicKey))
    XCTAssert(p2.pvssInstance.verify(shareBundle: s3, distributionBundle: distributionBundle, publicKey: p3.publicKey))
    XCTAssert(p3.pvssInstance.verify(shareBundle: s1, distributionBundle: distributionBundle, publicKey: p1.publicKey))
    XCTAssert(p3.pvssInstance.verify(shareBundle: s2, distributionBundle: distributionBundle, publicKey: p2.publicKey))
  
    // Receivers reconstruct the secret
    let shareBundles = [s1, s2, s3]
    
    guard let r1 = p1.pvssInstance.reconstruct(shareBundles: shareBundles, distributionBundle: distributionBundle),
      let r2 = p2.pvssInstance.reconstruct(shareBundles: shareBundles, distributionBundle: distributionBundle),
      let r3 = p3.pvssInstance.reconstruct(shareBundles: shareBundles, distributionBundle: distributionBundle) else {
        XCTFail()
        return
    }
    
    XCTAssertEqual(String(data: BigUInt(r1.description)!.serialize(), encoding: .utf8)!, secretMessage)
    XCTAssertEqual(String(data: BigUInt(r2.description)!.serialize(), encoding: .utf8)!, secretMessage)
    XCTAssertEqual(String(data: BigUInt(r3.description)!.serialize(), encoding: .utf8)!, secretMessage)
  }
  
  // Use fixed distribution bundle parameters for the tests
  func getDistributionBundle() -> DistributionBundle {
    let distributor = Participant(pvssInstance: pvssInstance, privateKey: privateKey, publicKey: pvssInstance.generatePublicKey(privateKey: privateKey))
    let polynomial = Polynomial(coefficients: [Bignum(164102006), Bignum(43489589), Bignum(98100795)])
    let threshold: Int = 3
    let privateKeys: [Bignum] = [Bignum(7901), Bignum(4801), Bignum(1453)]
    var publicKeys: [Bignum] = []
    let w: Bignum = Bignum(6345)
    
    for key in privateKeys {
      publicKeys.append(pvssInstance.generatePublicKey(privateKey: key))
    }
    
    return distributor.distribute(secret: secret, publicKeys: publicKeys, threshold: threshold, polynomial: polynomial, w: w)
  }
  
  // Use fixed share bundle for the tests
  func getShareBundle() -> ShareBundle {
    let distributionBundle = getDistributionBundle()
    
    // Calculate share bundle of participant P_1
    let privateKey: Bignum = Bignum(7901)
    let w: Bignum = 1337
    let participant = Participant(pvssInstance: pvssInstance, privateKey: privateKey, publicKey: pvssInstance.generatePublicKey(privateKey: privateKey))
    
    return participant.extractShare(distributionBundle: distributionBundle, privateKey: privateKey, w: w)!
  }
}
