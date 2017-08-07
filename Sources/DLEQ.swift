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
  let g1: Bignum
  let h1: Bignum
  let g2: Bignum
  let h2: Bignum
  
  let w: Bignum
  let q: Bignum
  let alpha: Bignum
  var c: Bignum?
  
  var a1: Bignum {
    return mod_exp(g1, w, q)
  }
  
  var a2: Bignum {
    return mod_exp(g2, w, q)
  }
  
  var r: Bignum? {
    if let c = c {
      return Bignum.modulus(w - (alpha * c), q - 1)
    } else {
      return nil
    }
  }
  
  init (g1: Bignum, h1: Bignum, g2: Bignum, h2: Bignum, length: Int, q: Bignum, alpha: Bignum, w: Bignum) {
    self.g1 = g1
    self.h1 = h1
    self.g2 = g2
    self.h2 = h2
    
    self.w = w
    self.q = q
    self.alpha = alpha
  }
  
  init(g1: Bignum, h1: Bignum, g2: Bignum, h2: Bignum, length: Int, q: Bignum, alpha: Bignum) {
    let w = Bignum(BigUInt.randomPrime(length: length).description) % q
    self.init(g1: g1, h1: h1, g2: g2, h2: h2, length: length, q: q, alpha: alpha, w: w)
  }
}
