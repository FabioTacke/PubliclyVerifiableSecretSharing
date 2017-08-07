//
//  Participant.swift
//  PVSS
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt
import Bignum
import CryptoSwift

/// A participant represents one party in the secret sharing scheme. The participant can share a secret among a group of other participants and is then called the "dealer". The receiving participants that receive a part of the secret can use it to reconstruct the secret Therefore the partticipants need to collaborate and exchange their parts.
public class Participant {
  public let pvssInstance: PVSSInstance
  public let privateKey: Bignum
  public let publicKey: Bignum
  
  public init(pvssInstance: PVSSInstance, privateKey: Bignum, publicKey: Bignum) {
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
  public func distribute(secret: Bignum, publicKeys: [Bignum], threshold: Int, polynomial: Polynomial, w: Bignum) -> DistributionBundle {
    assert(threshold <= publicKeys.count)
    
    // Data the distribution bundle is going to be consisting of
    var commitments: [Bignum] = []
    var positions: [Bignum: Int] = [:]
    var X: [Bignum: Bignum] = [:]
    var shares: [Bignum: Bignum] = [:]
    var challenge = SHA2(variant: .sha256)
    
    // Temp values
    var samplingPoints: [Bignum: Bignum] = [:]
    var a: [Bignum: (Bignum, Bignum)] = [:]
    var dleq_w: [Bignum: Bignum] = [:]
    var position: Int = 1
    
    // Calculate commitments C_j
    for j in 0..<threshold {
      commitments.append(mod_exp(pvssInstance.g, polynomial.coefficients[j], pvssInstance.q))
    }
    
    for key in publicKeys {
      positions[key] = position
      let samplingPoint = polynomial.getValue(x: Bignum(position)) % (pvssInstance.q - 1)
      samplingPoints[key] = samplingPoint
      
      // Calculate X_i
      var x: Bignum = 1
      var exponent: Bignum = 1
      for j in 0...threshold - 1 {
        x = (x * mod_exp(commitments[j], exponent, pvssInstance.q)) % pvssInstance.q
        exponent = (exponent * Bignum(position)) % (pvssInstance.q - 1)
      }
      X[key] = x
      
      // Calculate share Y_i
      let share = mod_exp(key, samplingPoint, pvssInstance.q)
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
    let challengeInt = Bignum(hex: challengeHash) % (pvssInstance.q - 1)
    
    // Calculate responses r_i
    var responses: [Bignum: Bignum] = [:]
    for key in publicKeys {
      if let x = X[key], let share = shares[key], let samplingPoint = samplingPoints[key], let w = dleq_w[key] {
        var dleq = DLEQ(g1: pvssInstance.g, h1: x, g2:key, h2: share, length: pvssInstance.length, q: pvssInstance.q, alpha: samplingPoint, w: w)
        dleq.c = challengeInt
        responses[key] = dleq.r!
      }
    }
    
    // Calculate U = sigma XOR SHA256(G^s)
    // sigma: secret to share
    let sharedValue = mod_exp(pvssInstance.G, polynomial.getValue(x: 0) % (pvssInstance.q - 1), pvssInstance.q)
    let sharedValueHash = sharedValue.description.sha256()
    let hashInt = Bignum(hex: sharedValueHash) % (pvssInstance.q)
    let U = Bignum((BigUInt(secret.description)! ^ BigUInt(hashInt.description)!).description)
    
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
  public func distribute(secret: Bignum, publicKeys: [Bignum], threshold: Int) -> DistributionBundle {
    let polynomial = Polynomial(degree: threshold - 1, bitLength: pvssInstance.length, q: pvssInstance.q)
    let w = Bignum((BigUInt.randomIntegerLessThan(BigUInt((pvssInstance.q).description)!)).description)
    return distribute(secret: secret, publicKeys: publicKeys, threshold: threshold, polynomial: polynomial, w: w)
  }
  
  /// Extracts the share from a given distribution bundle that is addressed to the calling participant. The extracted share is bundled with a proof which allows the other participants to verify the share's correctness.
  ///
  /// - Parameters:
  ///   - distributionBundle: The distribution bundle that consists the share to be extracted.
  ///   - privateKey: The participant's private key used to decrypt the share.
  ///   - w: An arbitrary chosen value needed for creating the proof that the share is correct.
  /// - Returns: The share bundle that is to be submitted to all the other participants in order to reconstruct the secret. It consists of the share itself and the proof that allows the receiving participant to verify its correctness. Return `nil` if the distribution bundle does not contain a share for the participant.
  public func extractShare(distributionBundle: DistributionBundle, privateKey: Bignum, w: Bignum) -> ShareBundle? {
    let publicKey = pvssInstance.generatePublicKey(privateKey: privateKey)
    guard let encryptedShare = distributionBundle.shares[publicKey] else {
      return nil
    }
    
    let share = mod_exp(encryptedShare, Bignum((BigUInt(privateKey.description)!.inverse(BigUInt(pvssInstance.q.description)! - 1)!).description), pvssInstance.q)
    
    var dleq = DLEQ(g1: pvssInstance.G, h1: publicKey, g2: share, h2: encryptedShare, length: pvssInstance.length, q: pvssInstance.q, alpha: privateKey, w: w)
    var digest = SHA2(variant: .sha256)
    let _ = try! digest.update(withBytes: publicKey.description.data(using: .utf8)!)
    let _ = try! digest.update(withBytes: encryptedShare.description.data(using: .utf8)!)
    let _ = try! digest.update(withBytes: dleq.a1.description.data(using: .utf8)!)
    let _ = try! digest.update(withBytes: dleq.a2.description.data(using: .utf8)!)
    let challengeHash = try! digest.finish().toHexString()
    let challengeInt = Bignum(hex: challengeHash) % (pvssInstance.q - 1)
    
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
  public func extractShare(distributionBundle: DistributionBundle, privateKey: Bignum) -> ShareBundle? {
    return extractShare(distributionBundle: distributionBundle, privateKey: privateKey, w: Bignum((BigUInt.randomInteger(withMaximumWidth: pvssInstance.length) % BigUInt(pvssInstance.q.description)!).description))
  }
}
