//
//  Extensions.swift
//  PVSS
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation

import BigInt

extension BigUInt {
  
  public static func randomPrime(length: Int) -> BigUInt {
    var random = BigUInt.randomInteger(withMaximumWidth: length)
    
    while !random.isPrime() {
      random = BigUInt.randomInteger(withMaximumWidth: length)
    }
    
    return random
  }
}

extension BigInt {
  
  public func mod(modulus: BigUInt) -> BigUInt {
    let abs = self.abs
    let div = abs.divided(by: modulus)
    
    if self.negative && div.remainder != 0 {
      let factor = BigInt(abs: div.quotient + 1, negative: true)
      return ((factor * BigInt(modulus)) - self).abs
    } else {
      return div.remainder
    }
  }
}
