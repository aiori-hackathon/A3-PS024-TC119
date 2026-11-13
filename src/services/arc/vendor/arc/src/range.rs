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

use alloc::vec::Vec;
use core::{iter::zip, num::NonZero};

use group::ff::{Field as _, PrimeField as _};
use rand_core::CryptoRngCore;
use sigma_proofs::traits::ScalarRng;
use subtle::{Choice, ConditionallySelectable as _};

use crate::{ArcError, Suite};

/// The associated witness values of a range proof.
pub(super) struct RangeProofWitness<S: Suite> {
    pub b: Vec<S::Scalar>,
    pub s: Vec<S::Scalar>,
    pub s2: Vec<S::Scalar>,
}

impl<S: Suite> RangeProofWitness<S> {
    /// Randomized generation of a [`RangeProofWitness`] for proving
    /// that `0 <= value < limit`.
    /// The `nonce_blinding` is the correlation used for the `s` blindings.
    pub fn new(
        csrng: &mut impl CryptoRngCore,
        value: u32,
        limit: NonZero<u32>,
        nonce_blinding: &S::Scalar,
    ) -> Result<Self, ArcError> {
        let (mut bits, bases) = bit_decompose(value, limit);
        if bases.len == 0 {
            return Ok(RangeProofWitness {
                b: vec![],
                s: vec![],
                s2: vec![],
            });
        }

        let zero = &S::Scalar::ZERO;
        let one = &S::Scalar::ONE;
        let b = bits
            .iter()
            .map(|&bit| S::Scalar::conditional_select(zero, one, bit))
            .collect();

        let last = bases.len - 1;
        let mut s = <S::Elt as ScalarRng>::random_scalars_vec(csrng, last);
        let partial_sum: S::Scalar = zip(bases.as_slice(), &s)
            .map(|(base, si)| S::Scalar::from_u128(u128::from(base.get())) * si)
            .sum();
        let mut s2 = zip(&bits, &s)
            .map(|(bit, si)| S::Scalar::conditional_select(si, zero, *bit))
            .collect::<Vec<_>>();

        let last_base = bases.elements[last].get();
        let s_last = S::Scalar::from_u128(u128::from(last_base))
            .invert()
            .into_option()
            .ok_or(ArcError::ProofFailed)?
            * (*nonce_blinding - partial_sum);
        s.push(s_last);
        s2.push(S::Scalar::conditional_select(&s_last, zero, bits[last]));
        bits.clear();

        Ok(RangeProofWitness { b, s, s2 })
    }
}

/// A binary decomposition of a value according to [`Bases`].
type Bits = Vec<Choice>;

/// The set of [`Bases`] used to express a `value` in the range `0 <= value < limit`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bases {
    elements: [NonZero<u32>; u32::BITS as usize],
    len: usize,
}

impl Bases {
    pub const fn as_slice(&self) -> &[NonZero<u32>] {
        self.elements.split_at(self.len).0
    }
}

/// Returns the bit decomposition of the value according to the bases.
///
/// The returned items hold
///
/// - n = [`ceil_log2`]\(limit)
/// - value = Bits\[0\] * Bases\[0\] + ... + Bits\[n-1] * Bases\[n-1]
/// - limit = 1 + Bases\[0\] + ... + Bases\[n-1\]
fn bit_decompose(value: u32, limit: NonZero<u32>) -> (Bits, Bases) {
    debug_assert!(value < limit.get(), "value out of range");

    let bases = compute_bases(limit);
    let mut bits = Vec::with_capacity(bases.len);
    let mut remainder = value;
    for base in bases.as_slice() {
        let (diff, has_overflowed) = remainder.overflowing_sub(base.get());
        let bit = !Choice::from(u8::from(has_overflowed));
        remainder.conditional_assign(&diff, bit);
        bits.push(bit)
    }

    debug_assert_eq!(remainder, 0, "value out of range");
    (bits, bases)
}

/// This is the ceiling of the logarithm base-2 of x, where x is a `u32` non-zero number.
#[inline]
pub(super) const fn ceil_log2(x: NonZero<u32>) -> u32 {
    u32::BITS - (x.get() - 1).leading_zeros()
}

/// Returns the base-2 expansion that represents n different values.
///
/// If n is a power of two, it returns the canonical bit decomposition.
/// Otherwise, it returns the canonical bit decomposition and the remainder.
///
/// Invariants:
/// - If n=1, then returns [].
/// - If n>1, none of the bases is zero.
/// - The sum of all bases is equal to n-1.
/// - Returned vector is sorted in decreasing order.
pub(super) const fn compute_bases(n: NonZero<u32>) -> Bases {
    let mut bases = Bases {
        elements: [NonZero::<u32>::MAX; u32::BITS as usize],
        len: n.ilog2() as usize,
    };

    let mut i = 0;
    while i < bases.len {
        if let Some(pow2) = NonZero::new(1 << (bases.len - i - 1)) {
            bases.elements[i] = pow2;
            i += 1;
        }
    }

    // Check if there is a positive remainder.
    if let Some(remainder) = n.get().checked_sub(1 << bases.len) {
        // Check if such a remainder is not zero.
        if let Some(mut rem) = NonZero::new(remainder) {
            // Find the position of the remainder in reverse order.
            let mut pos_remainder = 0;
            while pos_remainder < bases.len && bases.elements[pos_remainder].get() > remainder {
                pos_remainder += 1;
            }

            // Insert the remainder by shifting to the right the remaining elements.
            let mut j = pos_remainder;
            while j < bases.len {
                (bases.elements[j], rem) = (rem, bases.elements[j]);
                j += 1;
            }

            // The last element is inserted in the last position.
            bases.elements[j] = rem;
            bases.len += 1;
        }
    }

    bases
}

#[cfg(test)]
mod tests {
    use core::{iter::zip, num::NonZero};
    use subtle::ConditionallySelectable;

    #[test]
    fn ceil_log2() {
        // Python3
        // import math; [(i,math.ceil(math.log2(x))) for i in range(1,34)]
        let expected = [
            (0b1, 0),
            (0b10, 1),
            (0b11, 2),
            (0b100, 2),
            (0b101, 3),
            (0b110, 3),
            (0b111, 3),
            (0b1000, 3),
            (0b1001, 4),
            (0b1010, 4),
            (0b1011, 4),
            (0b1100, 4),
            (0b1101, 4),
            (0b1110, 4),
            (0b1111, 4),
            (0b10000, 4),
            (0b10001, 5),
            (0b10010, 5),
            (0b10011, 5),
            (0b10100, 5),
            (0b10101, 5),
            (0b10110, 5),
            (0b10111, 5),
            (0b11000, 5),
            (0b11001, 5),
            (0b11010, 5),
            (0b11011, 5),
            (0b11100, 5),
            (0b11101, 5),
            (0b11110, 5),
            (0b11111, 5),
            (0b100000, 5),
            (0b100001, 6),
        ];

        for (i, want) in expected {
            if let Some(n) = NonZero::new(i) {
                let got = super::ceil_log2(n);
                assert_eq!(got, want, "i: {} got: {} want: {}", i, got, want)
            }
        }
    }

    #[test]
    fn compute_bases() {
        for i in 1..33 {
            if let Some(n) = NonZero::new(i) {
                let bases = super::compute_bases(n);
                assert_eq!(
                    i - 1,
                    bases.as_slice().iter().map(|b| b.get()).sum(),
                    "sum of bases must add up to n-1. n = {} bases: {:?}",
                    i,
                    bases.as_slice()
                );
                assert!(
                    bases.as_slice().iter().is_sorted_by(|a, b| b.le(a)),
                    "bases are not sorted in reverse order. n = {} bases: {:?}",
                    i,
                    bases.as_slice()
                );
                assert!(
                    bases.as_slice().iter().all(|x| x.get() != 0),
                    "all bases must be non-zero. n = {} bases: {:?}",
                    i,
                    bases.as_slice()
                );
            }
        }
    }

    #[test]
    fn bit_decompose() {
        const MAX: NonZero<u32> = NonZero::new(33).expect("non-zero");
        for n in 0..MAX.get() {
            let (bits, bases) = super::bit_decompose(n, MAX);
            let got: u32 = zip(bits, bases.as_slice())
                .map(|(bit, base)| u32::conditional_select(&0, &base.get(), bit))
                .sum();
            let want = n;
            assert_eq!(got, want, "got: {} want: {}", got, want);
        }
    }

    #[test]
    #[should_panic]
    fn bit_decompose_invalid_range_1() {
        const ONE: NonZero<u32> = NonZero::<u32>::MIN;
        super::bit_decompose(1, ONE);
    }

    #[test]
    #[should_panic]
    fn bit_decompose_invalid_range_2() {
        const ONE: NonZero<u32> = NonZero::<u32>::MIN;
        super::bit_decompose(2, ONE);
    }
}
