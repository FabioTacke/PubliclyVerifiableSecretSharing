//
//  Participant.swift
//  PVSS
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt
import CryptoSwift

/// A participant represents one party in the secret sharing scheme. The participant can share a secret among a group of other participants and is then called the "dealer". The receiving participants that receive a part of the secret can use it to reconstruct the secret Therefore the partticipants need to collaborate and exchange their parts.
public class Participant {
  public let pvssInstance: PVSSInstance
  public let privateKey: BigUInt
  public let publicKey: BigUInt
  
  public init(pvssInstance: PVSSInstance, privateKey: BigUInt, publicKey: BigUInt) {
    self.pvssInstance = pvssInstance
    self.privateKey = privateKey
    self.publicKey = publicKey
  }
  
  public convenience init(pvssInstance: PVSSInstance) {
    let privateKey = pvssInstance.generatePrivateKey()
    let publicKey = pvssInstance.generatePublicKey(privateKey: privateKey)
    
    self.init(pvssInstance: pvssInstance, privateKey: privateKey, publicKey: publicKey)
  }
  
  /// Initializes a new participant with the default PVSS instance.
  public convenience init() {
    self.init(pvssInstance: PVSSInstance())
  }
  
  
  /// Takes a secret as input and returns the distribution bundle which is going to be submitted to all the participants the secret is going to be shared with. Those participants are specified by their public keys. They use the distribution bundle to verify that the shares are correct (without learning anything about the shares that are not supposed to be decrypted by them) and extract their encrypted shares. In fact, the distribution bundle can be published to everyone allowing even external parties to verify the integrity of the shares.
  ///
  /// - Parameters:
  ///   - secret: The value that is going to be shared among the other participants.
  ///   - publicKeys: Array of public keys of each participant the secret is to be shared with.
  ///   - threshold: The number of shares that is needed in order to reconstruct the secret. It must not be greater than the total number of participants.
  ///   - polynomial: The polynomial which is going to be used to produce sampling points which represent the shares. Those sampling points allow the receiving participants to reconstruct the polynomial and with it the secret. The degree of the polynomial must be `threshold`-1.
  ///   - w: An arbitrary chosen value needed for creating the proof that the shares in the distribution bundle are consistent.
  /// - Requires:
  ///   - `threshold` <= number of participants
  ///   - degree of polynomial = `threshold` - 1
  /// - Returns: The distribution bundle that is published so everyone (especially but not only the participants) can check the shares' integrity. Furthermore the participants extract their shares from it.
  public func distribute(secret: BigUInt, publicKeys: [BigUInt], threshold: Int, polynomial: Polynomial, w: BigUInt) -> DistributionBundle {
    assert(threshold <= publicKeys.count)
    
    // Data the distribution bundle is going to be consisting of
    var commitments: [BigUInt] = []
    var positions: [BigUInt: Int] = [:]
    var X: [BigUInt: BigUInt] = [:]
    var shares: [BigUInt: BigUInt] = [:]
    var challenge = SHA2(variant: .sha256)
    
    // Temp values
    var samplingPoints: [BigUInt: BigUInt] = [:]
    var a: [BigUInt: (BigUInt, BigUInt)] = [:]
    var dleq_w: [BigUInt: BigUInt] = [:]
    var position: Int = 1
    
    // Calculate commitments C_j
    for j in 0..<threshold {
      commitments.append(pvssInstance.g.power(polynomial.coefficients[j], modulus: pvssInstance.q))
    }
    
    for key in publicKeys {
      positions[key] = position
      let samplingPoint = polynomial.getValue(x: BigUInt(position)) % (pvssInstance.q - 1)
      samplingPoints[key] = samplingPoint
      
      // Calculate X_i
      var x: BigUInt = 1
      var exponent: BigUInt = 1
      for j in 0...threshold - 1 {
        x = (x * commitments[j].power(exponent, modulus: pvssInstance.q)) % pvssInstance.q
        exponent = (exponent * BigUInt(position)) % (pvssInstance.q - 1)
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
    
    // Calculate U = sigma XOR SHA256(G^s)
    // sigma: secret to share
    let sharedValue = pvssInstance.G.power(polynomial.getValue(x: 0) % (pvssInstance.q - 1), modulus: pvssInstance.q)
    let sharedValueHash = sharedValue.description.sha256()
    let hashInt = BigUInt(sharedValueHash, radix: 16)! % (pvssInstance.q)
    let U = secret ^ hashInt
    
    return DistributionBundle(commitments: commitments, positions: positions, shares: shares, publicKeys: publicKeys, challenge: challengeInt, responses: responses, U: U)
  }
  
  /// Experimental parallelized calculation of distribute method.
  public func distributeParallelized(secret: BigUInt, publicKeys: [BigUInt], threshold: Int, polynomial: Polynomial, w: BigUInt) -> DistributionBundle {
    assert(threshold <= publicKeys.count)
    
    // Data the distribution bundle is going to be consisting of
    var commitments: [BigUInt] = []
    var positions: [BigUInt: Int] = [:]
    var X: [BigUInt: BigUInt] = [:]
    var shares: [BigUInt: BigUInt] = [:]
    var challenge = SHA2(variant: .sha256)
    
    // Temp values
    var samplingPoints: [BigUInt: BigUInt] = [:]
    var a: [BigUInt: (BigUInt, BigUInt)] = [:]
    var dleq_w: [BigUInt: BigUInt] = [:]
    var position: Int = 1
    
    // Calculate commitments C_j
    let commitmentDispatchQueue = DispatchQueue(label: "commitmentDispatchQueue", attributes: .concurrent)
    let commitmentDispatchGroup = DispatchGroup()
    
    var tempCommitments: [Int: BigUInt] = [:]
    for j in 0..<threshold {
      commitmentDispatchGroup.enter()
      commitmentDispatchQueue.async {
        tempCommitments[j] = self.pvssInstance.g.power(polynomial.coefficients[j], modulus: self.pvssInstance.q)
        commitmentDispatchGroup.leave()
      }
    }
    
    commitmentDispatchGroup.wait()
    
    for j in 0..<threshold {
      commitments.append(tempCommitments[j]!)
    }
    
    // Calculate X_i
    for key in publicKeys {
      positions[key] = position
      let samplingPoint = polynomial.getValue(x: BigUInt(position)) % (self.pvssInstance.q - 1)
      samplingPoints[key] = samplingPoint
      
      var x: BigUInt = 1
      var exponent: BigUInt = 1
      for j in 0...threshold - 1 {
        x = (x * commitments[j].power(exponent, modulus: self.pvssInstance.q)) % self.pvssInstance.q
        exponent = (exponent * BigUInt(position)) % (self.pvssInstance.q - 1)
      }
      X[key] = x
      position += 1
    }
    
    let shareDispatchQueue = DispatchQueue(label: "asyncQueue", attributes: .concurrent)
    let shareDispatchGroup = DispatchGroup()
    
    for key in publicKeys {
      shareDispatchGroup.enter()
      shareDispatchQueue.async {
        let samplingPoint = samplingPoints[key]!
        let x = X[key]!
        
        // Calculate share Y_i
        let share = key.power(samplingPoint, modulus: self.pvssInstance.q)
        shares[key] = share
        
        // Calculate a_1i, a_2i (DLEQ)
        let dleq = DLEQ(g1: self.pvssInstance.g, h1: x, g2: key, h2: share, length: self.pvssInstance.length, q: self.pvssInstance.q, alpha: samplingPoint, w: w)
        dleq_w[key] = dleq.w
        a[key] = (dleq.a1, dleq.a2)
        shareDispatchGroup.leave()
      }
    }
    
    shareDispatchGroup.wait()
    
    for key in publicKeys {
      let x = X[key]!
      let share = shares[key]!
      let dleq = a[key]!
      
      // Update challenge hash
      let _ = try! challenge.update(withBytes: x.description.data(using: .utf8)!)
      let _ = try! challenge.update(withBytes: share.description.data(using: .utf8)!)
      let _ = try! challenge.update(withBytes: dleq.0.description.data(using: .utf8)!)
      let _ = try! challenge.update(withBytes: dleq.1.description.data(using: .utf8)!)
    }
    
    let challengeHash = try! challenge.finish().toHexString()
    let challengeInt = BigUInt(challengeHash, radix: 16)! % (pvssInstance.q - 1)
    
    // Calculate responses r_i
    let responseDispatchQueue = DispatchQueue(label: "responseQueue", attributes: .concurrent)
    let responseDispatchGroup = DispatchGroup()
    
    var responses: [BigUInt: BigUInt] = [:]
    for key in publicKeys {
      responseDispatchGroup.enter()
      responseDispatchQueue.async {
        if let x = X[key], let share = shares[key], let samplingPoint = samplingPoints[key], let w = dleq_w[key] {
          var dleq = DLEQ(g1: self.pvssInstance.g, h1: x, g2:key, h2: share, length: self.pvssInstance.length, q: self.pvssInstance.q, alpha: samplingPoint, w: w)
          dleq.c = challengeInt
          responses[key] = dleq.r!
        }
        responseDispatchGroup.leave()
      }
    }
    
    responseDispatchGroup.wait()
    
    // Calculate U = sigma XOR SHA256(G^s)
    // sigma: secret to share
    let sharedValue = pvssInstance.G.power(polynomial.getValue(x: 0) % (pvssInstance.q - 1), modulus: pvssInstance.q)
    let sharedValueHash = sharedValue.description.sha256()
    let hashInt = BigUInt(sharedValueHash, radix: 16)! % (pvssInstance.q)
    let U = secret ^ hashInt
    
    return DistributionBundle(commitments: commitments, positions: positions, shares: shares, publicKeys: publicKeys, challenge: challengeInt, responses: responses, U: U)
  }
  
  /// Takes a secret as input and returns the distribution bundle which is going to be submitted to all the participants the secret is going to be shared with. Those participants are specified by their public keys. They use the distribution bundle to verify that the shares are correct (without learning anything about the shares that are not supposed to be decrypted by them) and extract their encrypted shares. In fact, the distribution bundle can be published to everyone allowing even external parties to verify the integrity of the shares.
  ///
  /// - Parameters:
  ///   - secret: The value that is going to be shared among the other participants.
  ///   - publicKeys: Array of public keys of each participant the secret is to be shared with.
  ///   - threshold: The number of shares that is needed in order to reconstruct the secret. It must not be greater than the total number of participants.
  /// - Requires: `threshold` <= number of participants
  /// - Returns: The distribution bundle that is published so everyone (especially but not only the participants) can check the shares' integrity. Furthermore the participants extract their shares from it.
  public func distribute(secret: BigUInt, publicKeys: [BigUInt], threshold: Int) -> DistributionBundle {
    let polynomial = Polynomial(degree: threshold - 1, bitLength: pvssInstance.length, q: pvssInstance.q)
    let w = BigUInt.randomIntegerLessThan(pvssInstance.q)
    return distribute(secret: secret, publicKeys: publicKeys, threshold: threshold, polynomial: polynomial, w: w)
  }
  
  /// Experimental parallelized calculation of distribute method.
  public func distributeParallelized(secret: BigUInt, publicKeys: [BigUInt], threshold: Int) -> DistributionBundle {
    let polynomial = Polynomial(degree: threshold - 1, bitLength: pvssInstance.length, q: pvssInstance.q)
    let w = BigUInt.randomIntegerLessThan(pvssInstance.q)
    return distributeParallelized(secret: secret, publicKeys: publicKeys, threshold: threshold, polynomial: polynomial, w: w)
  }
  
  /// Extracts the share from a given distribution bundle that is addressed to the calling participant. The extracted share is bundled with a proof which allows the other participants to verify the share's correctness.
  ///
  /// - Parameters:
  ///   - distributionBundle: The distribution bundle that consists the share to be extracted.
  ///   - privateKey: The participant's private key used to decrypt the share.
  ///   - w: An arbitrary chosen value needed for creating the proof that the share is correct.
  /// - Returns: The share bundle that is to be submitted to all the other participants in order to reconstruct the secret. It consists of the share itself and the proof that allows the receiving participant to verify its correctness. Return `nil` if the distribution bundle does not contain a share for the participant.
  public func extractShare(distributionBundle: DistributionBundle, privateKey: BigUInt, w: BigUInt) -> ShareBundle? {
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
  
  /// Extracts the share from a given distribution bundle that is addressed to the calling participant. The extracted share is bundled with a proof which allows the other participants to verify the share's correctness.
  ///
  /// - Parameters:
  ///   - distributionBundle: The distribution bundle that consists the share to be extracted.
  ///   - privateKey: The participant's private key used to decrypt the share.
  /// - Returns: The share bundle that is to be submitted to all the other participants in order to reconstruct the secret. It consists of the share itself and the proof that allows the receiving participant to verify its correctness. Return `nil` if the distribution bundle does not contain a share for the participant.
  public func extractShare(distributionBundle: DistributionBundle, privateKey: BigUInt) -> ShareBundle? {
    return extractShare(distributionBundle: distributionBundle, privateKey: privateKey, w: BigUInt.randomInteger(withMaximumWidth: pvssInstance.length) % pvssInstance.q)
  }
}
