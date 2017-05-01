//
//  Bundles.swift
//  PVSS.swift
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt

public struct ShareBundle {
  let secret: BigUInt
  let challenge: BigUInt
  let response: BigUInt
}

public struct DistributionBundle {
  let commitments: [BigUInt]
  let shares: [BigUInt: BigUInt]
  let publicKeys: [BigUInt]
  let challenge: BigUInt
  let responses: [BigUInt: BigUInt]
}
