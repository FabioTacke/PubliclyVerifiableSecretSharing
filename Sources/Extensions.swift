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
  
  public static func modulus(_ a: BigInt,_ b: BigInt) -> BigUInt {
    let remainder = a.abs % b.abs
    return a.negative && !remainder.isEmpty ? b.abs - remainder : remainder
  }
}
