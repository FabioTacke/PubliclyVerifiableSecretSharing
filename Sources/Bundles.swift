//
//  Bundles.swift
//  PVSS
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt

public struct ShareBundle {
  let publicKey: BigUInt
  let share: BigUInt
  let challenge: BigUInt
  let response: BigUInt
}

public struct DistributionBundle {
  let commitments: [BigUInt]
  let positions: [BigUInt: Int]
  let shares: [BigUInt: BigUInt]
  let publicKeys: [BigUInt]
  let challenge: BigUInt
  let responses: [BigUInt: BigUInt]
  let U: BigUInt
}
