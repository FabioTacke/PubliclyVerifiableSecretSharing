//
//  DLEQ.swift
//  PVSS.swift
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt

public struct DLEQ {
  let g1: BigUInt
  let h1: BigUInt
  let g2: BigUInt
  let h2: BigUInt
  
  let w: BigUInt
  let q: BigUInt
  let alpha: BigUInt
  var c: BigUInt?
  
  var a1: BigUInt {
    return g1.power(w, modulus: q)
  }
  
  var a2: BigUInt {
    return g2.power(w, modulus: q)
  }
  
  var r: BigUInt? {
    if let c = c {
      return (BigInt(w) - BigInt(alpha * c)).mod(modulus: q-1)
    } else {
      return nil
    }
  }
  
  init (g1: BigUInt, h1: BigUInt, g2: BigUInt, h2: BigUInt, length: Int, q: BigUInt, alpha: BigUInt, w: BigUInt) {
    self.g1 = g1
    self.h1 = h1
    self.g2 = g2
    self.h2 = h2
    
    self.w = w
    self.q = q
    self.alpha = alpha
  }
  
  init(g1: BigUInt, h1: BigUInt, g2: BigUInt, h2: BigUInt, length: Int, q: BigUInt, alpha: BigUInt) {
    let w = BigUInt.randomPrime(length: length) % q
    self.init(g1: g1, h1: h1, g2: g2, h2: h2, length: length, q: q, alpha: alpha, w: w)
  }
}
