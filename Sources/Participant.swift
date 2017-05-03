//
//  Participant.swift
//  PVSS.swift
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt
import CryptoSwift

public class Participant {
  let pvssInstance: PVSSInstance
  let privateKey: BigUInt
  let publicKey: BigUInt
  
  init(pvssInstance: PVSSInstance, privateKey: BigUInt, publicKey: BigUInt) {
    self.pvssInstance = pvssInstance
    self.privateKey = privateKey
    self.publicKey = publicKey
  }
  
  convenience init(pvssInstance: PVSSInstance) {
    let privateKey = pvssInstance.generatePrivateKey()
    let publicKey = pvssInstance.generatePublicKey(privateKey: privateKey)
    
    self.init(pvssInstance: pvssInstance, privateKey: privateKey, publicKey: publicKey)
  }
  
  //  For now the secret cannot be chosen by the participant. Later function signature should look like this:
  //  func distribute(secret: BigUInt, publicKeys: [BigUInt], threshold: Int, polynomial: Polynomial, w: BigUInt) -> DistributionBundle {
  func distribute(publicKeys: [BigUInt], threshold: Int, polynomial: Polynomial, w: BigUInt) -> DistributionBundle {
    assert(threshold <= publicKeys.count)
    
    // Data the distribution bundle is going to be consisting of
    var commitments: [BigUInt] = []
    var positions: [BigUInt: BigUInt] = [:]
    var X: [BigUInt: BigUInt] = [:]
    var shares: [BigUInt: BigUInt] = [:]
    var challenge = SHA2(variant: .sha256)
    
    // Temp values
    var samplingPoints: [BigUInt: BigUInt] = [:]
    var a: [BigUInt: (BigUInt, BigUInt)] = [:]
    var dleq_w: [BigUInt: BigUInt] = [:]
    var position: BigUInt = 1
    
    // Calculate commitments C_j
    for j in 0..<threshold {
      commitments.append(pvssInstance.g.power(polynomial.coefficients[j], modulus: pvssInstance.q))
    }
    
    for key in publicKeys {
      positions[key] = position
      let samplingPoint = polynomial.getValue(x: position) % (pvssInstance.q - 1)
      samplingPoints[key] = samplingPoint
      
      // Calculate X_i
      var x: BigUInt = 1
      var exponent: BigUInt = 1
      for j in 0...threshold - 1 {
        x = (x * commitments[j].power(exponent, modulus: pvssInstance.q)) % pvssInstance.q
        exponent = (exponent * position) % (pvssInstance.q - 1)
      }
      X[key] = x
      
      // Calculate share Y_i
      let share = key.power(samplingPoint, modulus: pvssInstance.q)
      shares[key] = share
      
      // Calculate a_1i, a_2i (DLEQ)
      let dleq = DLEQ(g1: pvssInstance.g, h1: x, g2: key, h2: share, length: pvssInstance.length, q: pvssInstance.q, alpha: samplingPoint, w: w)
      dleq_w[key] = dleq.w
      a[key] = (dleq.a1, dleq.a2)
      
      // Update challenge hash
      let _ = try! challenge.update(withBytes: x.description.data(using: .utf8)!)
      let _ = try! challenge.update(withBytes: share.description.data(using: .utf8)!)
      let _ = try! challenge.update(withBytes: dleq.a1.description.data(using: .utf8)!)
      let _ = try! challenge.update(withBytes: dleq.a2.description.data(using: .utf8)!)
      
      position += 1
    }
    
    let challengeHash = try! challenge.finish().toHexString()
    let challengeInt = BigUInt(challengeHash, radix: 16)! % (pvssInstance.q - 1)
    
    // Calculate responses r_i
    var responses: [BigUInt: BigUInt] = [:]
    for key in publicKeys {
      if let x = X[key], let share = shares[key], let samplingPoint = samplingPoints[key], let w = dleq_w[key] {
        var dleq = DLEQ(g1: pvssInstance.g, h1: x, g2:key, h2: share, length: pvssInstance.length, q: pvssInstance.q, alpha: samplingPoint, w: w)
        dleq.c = challengeInt
        responses[key] = dleq.r!
      }
    }
    
    return DistributionBundle(commitments: commitments, positions: positions, shares: shares, publicKeys: publicKeys, challenge: challengeInt, responses: responses)
  }
  
  //  For now the secret cannot be chosen by the participant. Later function signature should look like this:
  //  func distribute(secret: BigUInt, publicKeys: [BigUInt], threshold: Int) -> DistributionBundle {
  func distribute(publicKeys: [BigUInt], threshold: Int) -> DistributionBundle {
    let polynomial = Polynomial(degree: threshold - 1, bitLength: pvssInstance.length)
    let w = BigUInt.randomPrime(length: pvssInstance.length) % pvssInstance.q
    return distribute(publicKeys: publicKeys, threshold: threshold, polynomial: polynomial, w: w)
  }
  
  func extractShare(distributionBundle: DistributionBundle, privateKey: BigUInt, w: BigUInt) -> ShareBundle? {
    let publicKey = pvssInstance.generatePublicKey(privateKey: privateKey)
    guard let encryptedShare = distributionBundle.shares[publicKey] else {
      return nil
    }
    
    let share = encryptedShare.power(privateKey.inverse(pvssInstance.q - 1)!, modulus: pvssInstance.q)
    
    var dleq = DLEQ(g1: pvssInstance.G, h1: publicKey, g2: share, h2: encryptedShare, length: pvssInstance.length, q: pvssInstance.q, alpha: privateKey, w: w)
    var digest = SHA2(variant: .sha256)
    let _ = try! digest.update(withBytes: publicKey.description.data(using: .utf8)!)
    let _ = try! digest.update(withBytes: encryptedShare.description.data(using: .utf8)!)
    let _ = try! digest.update(withBytes: dleq.a1.description.data(using: .utf8)!)
    let _ = try! digest.update(withBytes: dleq.a2.description.data(using: .utf8)!)
    let challengeHash = try! digest.finish().toHexString()
    let challengeInt = BigUInt(challengeHash, radix: 16)! % (pvssInstance.q - 1)
    
    dleq.c = challengeInt
    
    let shareBundle = ShareBundle(publicKey: publicKey, share: share, challenge: challengeInt, response: dleq.r!)
    
    return shareBundle
  }
  
  func extractShare(distributionBundle: DistributionBundle, privateKey: BigUInt) -> ShareBundle? {
    return extractShare(distributionBundle: distributionBundle, privateKey: privateKey, w: BigUInt.randomInteger(withMaximumWidth: pvssInstance.length) % pvssInstance.q)
  }
}
