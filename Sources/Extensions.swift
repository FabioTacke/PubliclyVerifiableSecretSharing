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
  
  public static func modulus(a: BigInt, b: BigInt) -> BigInt {
    if a.negative == b.negative {
      return BigInt(abs: a.abs % b.abs, negative: a.negative)
    }
    else {
      let floor = ((a / b) - 1) * b
      return BigInt(abs: (floor.abs - a.abs) % b.abs, negative: b.negative)
    }
  }
}
