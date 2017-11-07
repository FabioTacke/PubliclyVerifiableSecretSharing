//
//  DLEQ.swift
//  PVSS
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt
import Bignum

public struct DLEQ {
  public let g1: Bignum
  public let h1: Bignum
  public let g2: Bignum
  public let h2: Bignum
  
  public let w: Bignum
  public let q: Bignum
  public let alpha: Bignum
  public var c: Bignum?
  
  public var a1: Bignum {
    return mod_exp(g1, w, q)
  }
  
  public var a2: Bignum {
    return mod_exp(g2, w, q)
  }
  
  public var r: Bignum? {
    if let c = c {
      return Bignum.modulus(w - (alpha * c), q - 1)
    } else {
      return nil
    }
  }
  
  public init (g1: Bignum, h1: Bignum, g2: Bignum, h2: Bignum, length: Int, q: Bignum, alpha: Bignum, w: Bignum) {
    self.g1 = g1
    self.h1 = h1
    self.g2 = g2
    self.h2 = h2
    
    self.w = w
    self.q = q
    self.alpha = alpha
  }
  
  public init(g1: Bignum, h1: Bignum, g2: Bignum, h2: Bignum, length: Int, q: Bignum, alpha: Bignum) {
    let w = Bignum(BigUInt.randomPrime(length: length).description) % q
    self.init(g1: g1, h1: h1, g2: g2, h2: h2, length: length, q: q, alpha: alpha, w: w)
  }
}
