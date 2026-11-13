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

use curve25519_dalek::{RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_POINT};
use elliptic_curve::hash2curve::{ExpandMsg as _, ExpandMsgXmd, Expander as _};
use sha2::Sha512;

use crate::{ArcError, Suite};

/// Suite based on the quotient group ristretto255 ([RFC-9496](https://doi.org/10.17487/RFC9496)).
///
/// Available with `features = ["suite_ristretto255"]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ristretto255;

impl Suite for Ristretto255 {
    const NAME: &str = "Ristretto255";
    const CONTEXT: &[u8] = b"ARCV1-Ristretto255";
    type Elt = RistrettoPoint;
    type Scalar = Scalar;

    fn gen_g() -> Self::Elt {
        RISTRETTO_BASEPOINT_POINT
    }

    fn gen_h() -> Result<Self::Elt, ArcError> {
        let g = Self::gen_g().compress();
        Self::hash_to_group(g.as_bytes().as_ref(), b"generatorH")
    }

    fn hash_to_group(msg: &[u8], dst: &[u8]) -> Result<Self::Elt, ArcError> {
        // It follows method at https://www.rfc-editor.org/rfc/rfc9380.html#appendix-B
        let mut uniform_bytes = [0; 64];
        ExpandMsgXmd::<Sha512>::expand_message(&[msg], &[b"HashToGroup-", Self::CONTEXT, dst], 64)
            .map_err(|_| ArcError::UnrecognizedError)?
            .fill_bytes(&mut uniform_bytes);
        Ok(Self::Elt::from_uniform_bytes(&uniform_bytes))
    }

    fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Result<Self::Scalar, ArcError> {
        // It follows method at https://datatracker.ietf.org/doc/html/rfc9496#section-4.4
        let mut uniform_bytes = [0; 64];
        ExpandMsgXmd::<Sha512>::expand_message(&[msg], &[b"HashToScalar-", Self::CONTEXT, dst], 64)
            .map_err(|_| ArcError::UnrecognizedError)?
            .fill_bytes(&mut uniform_bytes);
        Ok(Self::Scalar::from_bytes_mod_order_wide(&uniform_bytes))
    }
}
