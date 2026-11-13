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

use core::array::from_fn;

use rand_core::CryptoRngCore;
use sigma_proofs::traits::ScalarRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{ArcError, Suite};

/// Public parameters of the algebraic MAC.
#[derive(Clone, Copy)]
pub(crate) struct IssuerParams<S: Suite, const N: usize> {
    pub x: [S::Elt; N],
}

/// Algebraic MAC secret key.
///
/// N determines the number of attributes of the MAC.
#[derive(ZeroizeOnDrop, Zeroize)]
pub(crate) struct SecretKey<S: Suite, const N: usize> {
    pub x: [S::Scalar; N],
    pub x0: S::Scalar,
}

impl<S: Suite, const N: usize> SecretKey<S, N> {
    /// Returns the [`IssuerParams`] corresponding to the [`SecretKey`].
    pub fn issuer_params(&self) -> Result<IssuerParams<S, N>, ArcError> {
        let gen_h = S::gen_h()?;
        Ok(IssuerParams {
            x: from_fn(|i| gen_h * self.x[i]),
        })
    }

    /// Randomized generation of a [`SecretKey`] from a
    /// cryptographically-secure random number generator (CSRNG).
    pub fn new(csrng: &mut impl CryptoRngCore) -> Self {
        Self {
            x0: <S::Elt as ScalarRng>::random_scalars::<1>(csrng)[0],
            x: <S::Elt as ScalarRng>::random_scalars::<N>(csrng),
        }
    }
}
