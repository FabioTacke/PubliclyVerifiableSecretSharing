//
//  PVSS_swift.swift
//  PVSS.swift
//
//  Created by Fabio Tacke on 26.04.17.
//
//

import BigInt

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
}
