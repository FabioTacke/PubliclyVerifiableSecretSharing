//
//  PVSSInstance.swift
//  PVSS
//
//  Created by Fabio Tacke on 26.04.17.
//
//

import BigInt
import CryptoSwift

/// A PVSSInstance represents an instance of a publicly verifiable secret sharing scheme, i.e. a set of parameters used for all the operations during the secret sharing process like distribution of the shared secret, extraction of the shares, reconstruction of the secret and verification of all the received messages.
public struct PVSSInstance {
  let q: BigUInt
  let g: BigUInt
  let G: BigUInt
  
  let length: Int
  
  public init(length: Int, q: BigUInt, g: BigUInt, G: BigUInt) {
    self.length = length
    self.q = q
    self.g = g
    self.G = G
  }
  
  /// Initializes a PVSSInstance by generating a safe prime of `length` bit length. `2` and the corresponding sophie germain prime are generators.
  ///
  /// - Parameter length: Number of bits used for choosing numbers and doing calculations.
  public init(length: Int) {
    // Find safe prime
    var q = BigUInt.randomInteger(withExactWidth: length)
    var sophieGermainCandidate: BigUInt
    
    repeat {
      repeat {
        q -= 2
      } while !q.isPrime()
      sophieGermainCandidate = (q-1).divided(by: 2).quotient
    } while !sophieGermainCandidate.isPrime()
    
    let g = sophieGermainCandidate
    let G = BigUInt(2)
    
    self.init(length: length, q: q, g: g, G: G)
  }
  
  /// Initializes a PVSSInstance with default parameters. `q` is a safe prime of length 2048 bit (RFC3526). `2` and the corresponding sophie germain prime are generators.
  public init() {
    let q = BigUInt(stringLiteral: "32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559")
    let g = (q-1).divided(by: 2).quotient
    let G = BigUInt(2)
    let length = 2048
    
    self.init(length: length, q: q, g: g, G: G)
  }
  
  public func generatePrivateKey() -> BigUInt {
    var key = BigUInt.randomIntegerLessThan(q)
    
    // We need the private key and q-1 to be coprime so that we can calculate 1/key mod (q-1) during secret reconstruction.
    while BigUInt.gcd(key, q - 1) != 1 {
      key = BigUInt.randomIntegerLessThan(q)
    }
    return key
  }
  
  public func generatePublicKey(privateKey: BigUInt) -> BigUInt {
    return G.power(privateKey, modulus: q)
  }
  
  /// Verifies that the shares the distribution bundle consists are consistent so that they can be used to reconstruct the secret later.
  ///
  /// - Parameter distributionBundle: The distribution bundle whose consistency is to be verified.
  /// - Returns: Returns `true` if the shares are correct and `false` otherwise.
  public func verify(distributionBundle: DistributionBundle) -> Bool {
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
    
    // Calculate challenge
    let challengeHash = try! digest.finish().toHexString()
    let challengeInt = BigUInt(challengeHash, radix: 16)! % (q - 1)
    
    return challengeInt == distributionBundle.challenge
  }
  
  /// Verifies if the share in the share bundle was decrypted correctly by the respective participant.
  ///
  /// - Parameters:
  ///   - shareBundle: The share bundle containing the share to be verified.
  ///   - distributionBundle: The distribution bundle that contains the share.
  ///   - publicKey: The public key of the sender of the share bundle.
  /// - Returns: Returns `true` if the share in the share bundle matches the decryption of the encrypted share and `false` otherwise.
  public func verify(shareBundle: ShareBundle, distributionBundle: DistributionBundle, publicKey: BigUInt) -> Bool {
    let shareCandidate = distributionBundle.shares[publicKey]
    guard let share = shareCandidate else {
      return false
    }
    return verify(shareBundle: shareBundle, encryptedShare: share)
  }
  
  /// Verifies if the share in the share bundle was decrypted correctly by the respective participant.
  ///
  /// - Parameters:
  ///   - shareBundle: The share bundle containing the share to be verified.
  ///   - encryptedShare: The encrypted share from the distribution bundle.
  /// - Returns: Returns `true` if the share in the share bundle matches the decryption of the encrypted share and `false` otherwise.
  public func verify(shareBundle: ShareBundle, encryptedShare: BigUInt) -> Bool {
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
  
  /// Processes the given shares and reconstructs the shared secret. The reconstruction may fail if the PVSSInstance parameters chosen by the dealer imply some mathematical limitations that concern inverting a number.
  ///
  /// - Parameters:
  ///   - shareBundles: Array of share bundles containing the shares to be processed.
  ///   - distributionBundle: The distribution bundle published by the dealer.
  ///
  /// - Returns: Returns the secret if the reconstruction process succeeded or `nil` if the reconstruction is not possible for the given set of shares due to mathematical limitations.
  public func reconstruct(shareBundles: [ShareBundle], distributionBundle: DistributionBundle) -> BigUInt? {
    if shareBundles.count < distributionBundle.commitments.count {
      return nil
    }
    
    var shares: [Int: BigUInt] = [:]
    
    for shareBundle in shareBundles {
      guard let position = distributionBundle.positions[shareBundle.publicKey] else {
        return nil
      }
      shares[position] = shareBundle.share
    }
    
    var secret: BigUInt = 1
    
    for (position, share) in shares {
      var exponent: BigUInt = 1
      let lagrangeCoefficient = PVSSInstance.lagrangeCoefficient(i: position, values: Array(shares.keys))
      
      if lagrangeCoefficient.numerator % lagrangeCoefficient.denominator == 0 {
        // Lagrange coefficient is an integer
        exponent = BigUInt(lagrangeCoefficient.numerator / abs(lagrangeCoefficient.denominator))
      } else {
        // Lagrange coefficient is a proper fraction
        // Cancel fraction if possible
        var numerator = BigUInt(lagrangeCoefficient.numerator)
        var denominator = BigUInt(abs(lagrangeCoefficient.denominator))
        let gcd = BigUInt.gcd(numerator, denominator)
        numerator = numerator.divided(by: gcd).quotient
        denominator = denominator.divided(by: gcd).quotient
        
        if let inverseDenominator = denominator.inverse(q - 1) {
          exponent = (numerator * inverseDenominator) % (q - 1)
        } else {
          // Denominator of Lagrange coefficient fraction does not have an inverse. Share cannot be processed.
          return nil
        }
      }
      var factor = share.power(exponent, modulus: q)
      if lagrangeCoefficient.numerator * lagrangeCoefficient.denominator < 0 {
        // Lagrange coefficient was negative. S^(-lambda) = 1/(S^lambda)
        if let inverseFactor = factor.inverse(q) {
          factor = inverseFactor
        } else {
          return nil
        }
      }
      secret = (secret * factor) % q
    }
    
    // Recover the secret sigma = H(G^s) XOR U
    let sharedSecretHash = secret.description.sha256()
    let hashInt = BigUInt(sharedSecretHash, radix: 16)! % q
    let decryptedSecret = hashInt ^ distributionBundle.U
    
    return decryptedSecret
  }
  
  public static func lagrangeCoefficient(i: Int, values: [Int]) -> (numerator: Int, denominator: Int) {
    if !values.contains(i) {
      return (0, 1)
    }
    
    var numerator: Int = 1
    var denominator: Int = 1
    
    for j in 1...values.max()! {
      if j != i && values.contains(j) {
        numerator *= j
        denominator *= (j-i)
      }
    }
    
    return (numerator, denominator)
  }
}
