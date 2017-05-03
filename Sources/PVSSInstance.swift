//
//  PVSS_swift.swift
//  PVSS.swift
//
//  Created by Fabio Tacke on 26.04.17.
//
//

import BigInt
import CryptoSwift

public struct PVSSInstance {
  let q: BigUInt
  let g: BigUInt
  let G: BigUInt
  
  let length: Int
  
  init(length: Int, q: BigUInt, g: BigUInt, G: BigUInt) {
    self.length = length
    self.q = q
    self.g = g
    self.G = G
  }
  
  init(length: Int) {
    let q = BigUInt.randomPrime(length: length)
    
    let g = BigUInt.randomPrime(length: length) % q
    let G = BigUInt.randomPrime(length: length) % q
    
    self.init(length: length, q: q, g: g, G: G)
  }
  
  func generatePrivateKey() -> BigUInt {
    return BigUInt.randomPrime(length: length) % q
  }
  
  func generatePublicKey(privateKey: BigUInt) -> BigUInt {
    return G.power(privateKey, modulus: q)
  }
  
  func verify(distributionBundle: DistributionBundle) -> Bool {
    var digest = SHA2(variant: .sha256)
    
    for key in distributionBundle.publicKeys {
      guard let position = distributionBundle.positions[key],
        let response = distributionBundle.responses[key],
        let share = distributionBundle.shares[key] else {
          return false
      }
      
      // Calculate X_i
      var x: BigUInt = 1
      var exponent: BigUInt = 1
      for j in 0..<distributionBundle.commitments.count {
        x = (x * distributionBundle.commitments[j].power(exponent, modulus: q)) % q
        exponent = (exponent * BigUInt(position)) % (q - 1)
      }
      
      // Calculate a_1i, a_2i
      
      let a1 = (g.power(response, modulus: q) * x.power(distributionBundle.challenge, modulus: q)) % q
      let a2 = (key.power(response, modulus: q) * (share.power(distributionBundle.challenge, modulus: q))) % q
      
      // Update hash
      let _ = try! digest.update(withBytes: x.description.data(using: .utf8)!)
      let _ = try! digest.update(withBytes: share.description.data(using: .utf8)!)
      let _ = try! digest.update(withBytes: a1.description.data(using: .utf8)!)
      let _ = try! digest.update(withBytes: a2.description.data(using: .utf8)!)
    }
    
    let challengeHash = try! digest.finish().toHexString()
    let challengeInt = BigUInt(challengeHash, radix: 16)! % (q - 1)
    
    return challengeInt == distributionBundle.challenge
  }
  
  func verify(shareBundle: ShareBundle, encryptedShare: BigUInt) -> Bool {
    var digest = SHA2(variant: .sha256)
    
    let a1 = (G.power(shareBundle.response, modulus: q) * shareBundle.publicKey.power(shareBundle.challenge, modulus: q)) % q
    let a2 = (shareBundle.share.power(shareBundle.response, modulus: q) * encryptedShare.power(shareBundle.challenge, modulus: q)) % q
    
    let _ = try! digest.update(withBytes: shareBundle.publicKey.description.data(using: .utf8)!)
    let _ = try! digest.update(withBytes: encryptedShare.description.data(using: .utf8)!)
    let _ = try! digest.update(withBytes: a1.description.data(using: .utf8)!)
    let _ = try! digest.update(withBytes: a2.description.data(using: .utf8)!)
    
    let challengeHash = try! digest.finish().toHexString()
    let challengeInt = BigUInt(challengeHash, radix: 16)! % (q - 1)
    
    return challengeInt == shareBundle.challenge
  }
}
