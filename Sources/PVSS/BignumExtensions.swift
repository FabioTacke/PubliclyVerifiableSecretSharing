//
//  BignumExtensions.swift
//  PVSS
//
//  Created by Fabio Tacke on 06.08.17.
//
//

import Foundation
import Bignum
import CryptoSwift

extension Bignum: Hashable {
  public var hashValue: Int {
    return 0
  }
}

extension Bignum {
  
  public var abs: Bignum {
    return self * self.sign
  }
  
  public static func modulus(_ a: Bignum,_ b: Bignum) -> Bignum {
    let remainder = a.abs % b.abs
    return a.isNegative() && !remainder.isZero() ? b.abs - remainder : remainder
  }
}
