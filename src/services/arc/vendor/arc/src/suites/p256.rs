// Copyright (c) 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use p256::{
    NistP256, ProjectivePoint, Scalar,
    elliptic_curve::{
        group::GroupEncoding as _,
        hash2curve::{ExpandMsgXmd, GroupDigest as _},
    },
};
use sha2::Sha256;

use crate::{ArcError, Suite};

/// Suite based on the P256 prime order elliptic curve (NIST secp256r1).
///
/// Available with `features = ["suite_p256"]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P256;

impl Suite for P256 {
    const NAME: &str = "P256";
    const CONTEXT: &[u8] = b"ARCV1-P256";
    type Elt = ProjectivePoint;
    type Scalar = Scalar;

    fn gen_g() -> Self::Elt {
        ProjectivePoint::GENERATOR
    }

    fn gen_h() -> Result<Self::Elt, ArcError> {
        let g = Self::gen_g().to_bytes();
        Self::hash_to_group(&g, b"generatorH")
    }

    fn hash_to_group(msg: &[u8], dst: &[u8]) -> Result<Self::Elt, ArcError> {
        NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
            &[msg],
            &[b"HashToGroup-", Self::CONTEXT, dst],
        )
        .map_err(|_| ArcError::UnrecognizedError)
    }

    fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Result<Self::Scalar, ArcError> {
        NistP256::hash_to_scalar::<ExpandMsgXmd<Sha256>>(
            &[msg],
            &[b"HashToScalar-", Self::CONTEXT, dst],
        )
        .map_err(|_| ArcError::UnrecognizedError)
    }
}
