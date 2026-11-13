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

// Modified by TokenForge for checked inputs and same-object verified-tag output.
use alloc::vec::Vec;
use core::{array::from_fn, iter::zip, num::NonZero};

use group::{
    Group as _,
    ff::{Field as _, PrimeField as _},
};
use rand_core::CryptoRngCore;
use sigma_proofs::{
    LinearRelation, Nizk, linear_relation::GroupVar,
    spec_compat::CanonicalLinearRelationCompatible as CanonicalLinearRelation, traits::ScalarRng,
};
use spongefish::NargSerialize as _;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    ArcError, Suite, elt_bytes_len, mac,
    range::{RangeProofWitness, ceil_log2, compute_bases},
    scalar_bytes_len,
    serde::{Des, Ser},
};

/// Number of attributes to be MAC-ed.
const NUM_ATTRS: usize = 2;

type Commitment<S> = <S as Suite>::Elt;
type Randomness<S> = <S as Suite>::Scalar;
type Ciphertext<S> = <S as Suite>::Elt;
type NikzElt<S> = Nizk<CanonicalLinearRelation<<S as Suite>::Elt>>;

// ElGamal_encryption
fn encrypt<S: Suite>(secret: &Secret<S>, base_g: S::Elt, base_h: S::Elt) -> Ciphertext<S> {
    base_g * secret.msg + base_h * secret.rand
}

fn pedersen_commitment<S: Suite>(
    input: &S::Scalar,
    base_g: S::Elt,
    rand: &Randomness<S>,
    base_h: S::Elt,
) -> Commitment<S> {
    base_g * input + base_h * rand
}

/// Public parameters of the Issuer used for generating a [`Credential`].
#[derive(Clone, Copy)]
pub struct IssuerParams<S: Suite> {
    mac_params: mac::IssuerParams<S, NUM_ATTRS>,
    x0_com: Commitment<S>,
}

impl<S: Suite> IssuerParams<S> {
    /// Length in bytes of its serialized format.
    #[must_use]
    pub fn bytes_len() -> usize {
        elt_bytes_len::<S>() * (1 + NUM_ATTRS)
    }

    /// Serializes to its binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        Ser::new(Self::bytes_len())
            .add(&self.x0_com)
            .add(&self.mac_params.x)
            .end()
    }

    /// Recovers from its binary format.
    ///
    /// The slice length must match the value returned by [`Self::bytes_len`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, ArcError> {
        let mut d = Des::new(b, Self::bytes_len())?;
        let params = Self {
            x0_com: d.get_element()?,
            mac_params: mac::IssuerParams {
                x: [d.get_element()?, d.get_element()?],
            },
        };
        d.end(params)
    }
}

/// Secret key of the Issuer.
///
/// It is used to generate [`CredentialResponse`] in response to a [`CredentialRequest`] from the Client.
/// It is also used to verify a given [`Presentation`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<S: Suite> {
    mac_key: mac::SecretKey<S, NUM_ATTRS>,
    x0_rand: Randomness<S>,
}

impl<S: Suite> SecretKey<S> {
    /// Samples a new [`SecretKey`] from a cryptographically-secure random number generator (CSRNG).
    pub fn new(csrng: &mut impl CryptoRngCore) -> Self {
        Self {
            mac_key: mac::SecretKey::new(csrng),
            x0_rand: <S::Elt as ScalarRng>::random_scalars::<1>(csrng)[0],
        }
    }

    /// Returns the [`IssuerParams`] corresponding to this [`SecretKey`].
    pub fn issuer_params(&self) -> Result<IssuerParams<S>, ArcError> {
        let g = S::gen_g();
        let h = S::gen_h()?;
        Ok(IssuerParams {
            mac_params: self.mac_key.issuer_params()?,
            x0_com: pedersen_commitment::<S>(&self.mac_key.x0, g, &self.x0_rand, h),
        })
    }

    /// Length in bytes of its serialized format.
    #[must_use]
    pub const fn bytes_len() -> usize {
        scalar_bytes_len::<S>() * (2 + NUM_ATTRS)
    }

    /// Serializes to its binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        Ser::new(Self::bytes_len())
            .add(&self.mac_key.x0)
            .add(&self.mac_key.x)
            .add(&self.x0_rand)
            .end()
    }

    /// Recovers from its binary format.
    ///
    /// The slice length must match the value returned by [`Self::bytes_len`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, ArcError> {
        let mut d = Des::new(b, Self::bytes_len())?;
        let key = Self {
            mac_key: mac::SecretKey {
                x0: d.get()?,
                x: d.get()?,
            },
            x0_rand: d.get()?,
        };
        d.end(key)
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Secret<S: Suite> {
    msg: S::Scalar,
    rand: Randomness<S>,
}

/// [`ClientSecret`] used for generating a [`Credential`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClientSecret<S: Suite>([Secret<S>; NUM_ATTRS]);

impl<S: Suite> ClientSecret<S> {
    /// Length in bytes of its serialized format.
    #[must_use]
    pub const fn bytes_len() -> usize {
        scalar_bytes_len::<S>() * 2 * NUM_ATTRS
    }

    /// Serializes to its binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        Ser::new(Self::bytes_len())
            .add(&self.0[0].msg)
            .add(&self.0[0].rand)
            .add(&self.0[1].msg)
            .add(&self.0[1].rand)
            .end()
    }

    /// Recovers from its binary format.
    ///
    /// The slice length must match the value returned by [`Self::bytes_len`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, ArcError> {
        let mut d = Des::new(b, Self::bytes_len())?;
        let secret = Self([
            Secret {
                msg: d.get()?,
                rand: d.get()?,
            },
            Secret {
                msg: d.get()?,
                rand: d.get()?,
            },
        ]);
        d.end(secret)
    }
}

/// The Client sends a [`CredentialRequest`] to the Issuer for generating a [`Credential`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CredentialRequest<S: Suite> {
    encrypted_messages: [Ciphertext<S>; NUM_ATTRS],
    proof: Vec<u8>,
}

impl<S: Suite> CredentialRequest<S> {
    // Domain separation tag for secret generation.
    const REQUEST_CONTEXT_DST: &[u8] = b"requestContext";

    /// Tag used for generating zero-knowledge proofs.
    const TAG: &[u8] = b"CredentialRequest";

    /// Randomized generation of a [`CredentialRequest`] bound to an arbitrary `request_context`.
    ///
    /// It also returns the [`ClientSecret`] that must be used to generate a [`Credential`], once the
    /// Issuer replies with a [`CredentialResponse`].
    pub fn new(
        csrng: &mut impl CryptoRngCore,
        request_context: &[u8],
    ) -> Result<(Self, ClientSecret<S>), ArcError> {
        let [msg1, rand1, rand2] = <S::Elt as ScalarRng>::random_scalars(csrng);
        let secrets = ClientSecret([
            Secret {
                msg: msg1,
                rand: rand1,
            },
            Secret {
                msg: S::hash_to_scalar(request_context, Self::REQUEST_CONTEXT_DST)?,
                rand: rand2,
            },
        ]);
        let g = S::gen_g();
        let h = S::gen_h()?;
        let encrypted_messages = from_fn(|i| encrypt(&secrets.0[i], g, h));
        let witness = [
            secrets.0[0].msg,
            secrets.0[1].msg,
            secrets.0[0].rand,
            secrets.0[1].rand,
        ]
        .to_vec();
        let nikz = Self::build_statement(encrypted_messages, g, h)?;
        let proof = nikz
            .prove_compact(&witness, csrng)
            .map_err(ArcError::from_sigma)?;
        let request = CredentialRequest {
            encrypted_messages,
            proof,
        };

        Ok((request, secrets))
    }

    /// Builds the statement to be proven or verified by the proof system.
    fn build_statement(
        encrypted_messages: [Ciphertext<S>; NUM_ATTRS],
        g: S::Elt,
        h: S::Elt,
    ) -> Result<NikzElt<S>, ArcError> {
        let mut statement = LinearRelation::new();
        let gen_g = statement.allocate_element_with(g);
        let gen_h = statement.allocate_element_with(h);

        let [m1, m2, r1, r2] = statement.allocate_scalars();
        let m1_encrypted = statement.allocate_element_with(encrypted_messages[0]);
        statement.append_equation(m1_encrypted, gen_g * m1 + gen_h * r1);
        let m2_encrypted = statement.allocate_element_with(encrypted_messages[1]);
        statement.append_equation(m2_encrypted, gen_g * m2 + gen_h * r2);

        CanonicalLinearRelation::new_from_lr(statement)
            .into_nizk(&[S::CONTEXT, Self::TAG].concat())
            .map_err(ArcError::from_sigma)
    }

    /// Length in bytes of the serialized proof.
    const fn proof_len() -> usize {
        scalar_bytes_len::<S>() * 5
    }

    /// Length in bytes of its serialized format.
    #[must_use]
    pub fn bytes_len() -> usize {
        elt_bytes_len::<S>() * NUM_ATTRS + Self::proof_len()
    }

    /// Serializes to its binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        Ser::new(Self::bytes_len())
            .add(&self.encrypted_messages)
            .add(&self.proof)
            .end()
    }

    /// Recovers from its binary format.
    ///
    /// The slice length must match the value returned by [`Self::bytes_len`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, ArcError> {
        let mut d = Des::new(b, Self::bytes_len())?;
        let request = Self {
            encrypted_messages: [d.get_element()?, d.get_element()?],
            proof: d.get_bytes(Self::proof_len())?,
        };
        d.end(request)
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct CredentialResponseInner<S: Suite> {
    u: S::Elt,
    u_prime_encrypted: S::Elt,
    x_aux: [S::Elt; NUM_ATTRS],
    x0_aux: S::Elt,
    h_aux: S::Elt,
}

/// The Issuer sends a [`CredentialResponse`] to the Client for generating a [`Credential`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CredentialResponse<S: Suite> {
    inner: CredentialResponseInner<S>,
    proof: Vec<u8>,
}

impl<S: Suite> CredentialResponse<S> {
    /// Tag used for generating zero-knowledge proofs.
    const TAG: &[u8] = b"CredentialResponse";

    /// Randomized generation of a [`CredentialResponse`] in response to a [`CredentialRequest`] from the Client.
    pub fn new(
        csrng: &mut impl CryptoRngCore,
        key: &SecretKey<S>,
        request: CredentialRequest<S>,
    ) -> Result<Self, ArcError> {
        let gen_g = S::gen_g();
        let gen_h = S::gen_h()?;
        CredentialRequest::<S>::build_statement(request.encrypted_messages, gen_g, gen_h)?
            .verify_compact(&request.proof)
            .map_err(ArcError::from_sigma)?;

        let params = key.issuer_params()?;
        let [b] = <S::Elt as ScalarRng>::random_scalars(csrng);
        let inner = CredentialResponseInner {
            u: gen_g * b,
            u_prime_encrypted: zip(&request.encrypted_messages, key.mac_key.x.iter())
                .fold(params.x0_com, |acc, (mi, xi)| acc + (*mi * xi))
                * b,
            x0_aux: gen_h * (b * key.x0_rand),
            x_aux: params.mac_params.x.map(|xi| xi * b),
            h_aux: gen_h * b,
        };
        let witness = [
            key.mac_key.x0,
            key.mac_key.x[0],
            key.mac_key.x[1],
            key.x0_rand,
            b,
            b * key.mac_key.x[0],
            b * key.mac_key.x[1],
        ]
        .to_vec();
        let proof = Self::build_statement(&params, request, &inner, gen_g, gen_h)?
            .prove_compact(&witness, csrng)
            .map_err(ArcError::from_sigma)?;

        Ok(Self { inner, proof })
    }

    /// Builds the statement to be proven or verified by the proof system.
    fn build_statement(
        params: &IssuerParams<S>,
        request: CredentialRequest<S>,
        inner: &CredentialResponseInner<S>,
        g: S::Elt,
        h: S::Elt,
    ) -> Result<NikzElt<S>, ArcError> {
        let mut statement = LinearRelation::new();
        let [x0_var, x1_var, x2_var, xb_var, b_var, t1_var, t2_var] = statement.allocate_scalars();
        #[allow(non_snake_case)]
        let [
            gen_G_var,
            gen_H_var,
            m1_enc_var,
            m2_enc_var,
            U_var,
            enc_U_prime_var,
            X0_var,
            X1_var,
            X2_var,
            X0_aux_var,
            X1_aux_var,
            X2_aux_var,
            H_aux_var,
        ] = statement.allocate_elements();
        statement.set_elements([
            (gen_G_var, g),
            (gen_H_var, h),
            (m1_enc_var, request.encrypted_messages[0]),
            (m2_enc_var, request.encrypted_messages[1]),
            (U_var, inner.u),
            (enc_U_prime_var, inner.u_prime_encrypted),
            (X0_var, params.x0_com),
            (X1_var, params.mac_params.x[0]),
            (X2_var, params.mac_params.x[1]),
            (X0_aux_var, inner.x0_aux),
            (X1_aux_var, inner.x_aux[0]),
            (X2_aux_var, inner.x_aux[1]),
            (H_aux_var, inner.h_aux),
        ]);

        // 1. X0 = x0 * generatorG + x0Blinding * generatorH
        statement.append_equation(X0_var, x0_var * gen_G_var + xb_var * gen_H_var);

        // 2. X1 = x1 * generatorH
        statement.append_equation(X1_var, x1_var * gen_H_var);
        // 3. X2 = x2 * generatorH
        statement.append_equation(X2_var, x2_var * gen_H_var);

        // 4. X0Aux = b * x0Blinding * generatorH
        // 4a. HAux = b * generatorH
        // 4b: X0Aux = x0Blinding * HAux (= b * x0Blinding * generatorH)
        statement.append_equation(H_aux_var, b_var * gen_H_var);
        statement.append_equation(X0_aux_var, xb_var * H_aux_var);

        // 5. X1Aux = b * x1 * generatorH
        // 5a. X1Aux = t1 * generatorH (t1 = b * x1)
        // 5b. X1Aux = b * X1 (X1 = x1 * generatorH)
        statement.append_equation(X1_aux_var, t1_var * gen_H_var);
        statement.append_equation(X1_aux_var, b_var * X1_var);

        // 6. X2Aux = b * x2 * generatorH
        // 6a. X2Aux = b * X2 (X2 = x2 * generatorH)
        // 6b. X2Aux = t2 * H (t2 = b * x2)
        statement.append_equation(X2_aux_var, b_var * X2_var);
        statement.append_equation(X2_aux_var, t2_var * gen_H_var);

        // 7. U = b * generatorG
        statement.append_equation(U_var, b_var * gen_G_var);

        // 8. encUPrime = b * (X0 + x1 * Enc(m1) + x2 * Enc(m2))
        // simplified: encUPrime = b * X0 + t1 * m1Enc + t2 * m2Enc, since t1 = b * x1 and t2 = b * x2
        statement.append_equation(
            enc_U_prime_var,
            b_var * X0_var + t1_var * m1_enc_var + t2_var * m2_enc_var,
        );

        CanonicalLinearRelation::new_from_lr(statement)
            .into_nizk(&[S::CONTEXT, Self::TAG].concat())
            .map_err(ArcError::from_sigma)
    }

    /// Length in bytes of the serialized proof.
    const fn proof_len() -> usize {
        scalar_bytes_len::<S>() * 8
    }

    /// Length in bytes of its serialized format.
    #[must_use]
    pub fn bytes_len() -> usize {
        elt_bytes_len::<S>() * (4 + NUM_ATTRS) + Self::proof_len()
    }

    /// Serializes to its binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        Ser::new(Self::bytes_len())
            .add(&self.inner.u)
            .add(&self.inner.u_prime_encrypted)
            .add(&self.inner.x0_aux)
            .add(&self.inner.x_aux)
            .add(&self.inner.h_aux)
            .add(&self.proof)
            .end()
    }

    /// Recovers from its binary format.
    ///
    /// The slice length must match the value returned by [`Self::bytes_len`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, ArcError> {
        let mut d = Des::new(b, Self::bytes_len())?;
        let response = Self {
            inner: CredentialResponseInner {
                u: d.get_element()?,
                u_prime_encrypted: d.get_element()?,
                x0_aux: d.get_element()?,
                x_aux: [d.get_element()?, d.get_element()?],
                h_aux: d.get_element()?,
            },
            proof: d.get_bytes(Self::proof_len())?,
        };
        d.end(response)
    }
}

/// A [`Credential`] that the Client holds to generate multiple [`Presentation`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Credential<S: Suite> {
    u: S::Elt,
    u_prime: S::Elt,
    m1: S::Scalar,
    x1: S::Elt,
}

impl<S: Suite> Credential<S> {
    /// A [`Credential`] is generated from a [`CredentialRequest`] and
    /// [`ClientSecret`], the [`CredentialResponse`] sent by the Issuer,
    /// and the public [`IssuerParams`] of the Issuer.
    pub fn new(
        params: &IssuerParams<S>,
        request: CredentialRequest<S>,
        secrets: ClientSecret<S>,
        response: CredentialResponse<S>,
    ) -> Result<Self, ArcError> {
        let gen_g = S::gen_g();
        let gen_h = S::gen_h()?;
        CredentialResponse::build_statement(params, request, &response.inner, gen_g, gen_h)?
            .verify_compact(&response.proof)
            .map_err(ArcError::from_sigma)?;

        Ok(Self {
            u: response.inner.u,
            u_prime: (0..NUM_ATTRS).fold(
                response.inner.u_prime_encrypted - response.inner.x0_aux,
                |acc, i| acc - response.inner.x_aux[i] * secrets.0[i].rand,
            ),
            m1: secrets.0[0].msg,
            x1: params.mac_params.x[0],
        })
    }

    /// Generates a [`State`] that produces a `presentation_limit` number
    /// of [`Presentation`]s bound to an arbitrary `presentation_context`.
    ///
    /// # Errors
    ///
    /// Returns [`ArcError::InvalidContextLength`] if `presentation_context`
    /// exceeds [`u32::MAX`] bytes.
    pub fn presentation_state(
        &self,
        presentation_limit: NonZero<u32>,
        presentation_context: &[u8],
    ) -> Result<State<S>, ArcError> {
        if u32::try_from(presentation_context.len()).is_err() {
            return Err(ArcError::InvalidContextLength);
        }

        Ok(State {
            credential: Credential { ..*self },
            presentation_context_tag: S::hash_to_group(
                presentation_context,
                Presentation::<S>::TAG_DST,
            )?,
            presentation_limit,
            presentations_used: 0,
        })
    }

    /// Length in bytes of its serialized format.
    #[must_use]
    pub fn bytes_len() -> usize {
        elt_bytes_len::<S>() * 3 + scalar_bytes_len::<S>()
    }

    /// Serializes to its binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        Ser::new(Self::bytes_len())
            .add(&self.u)
            .add(&self.u_prime)
            .add(&self.m1)
            .add(&self.x1)
            .end()
    }

    /// Recovers from its binary format.
    ///
    /// The slice length must match the value returned by [`Self::bytes_len`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, ArcError> {
        let mut d = Des::new(b, Self::bytes_len())?;
        let credential = Self {
            u: d.get_element()?,
            u_prime: d.get_element()?,
            m1: d.get()?,
            x1: d.get_element()?,
        };
        d.end(credential)
    }
}

/// A [`State`] is generated from a [`Credential`] and is bound to a presentation context.
///
/// Clients use a [`State`] to generate a [`Presentation`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct State<S: Suite> {
    credential: Credential<S>,
    presentation_context_tag: S::Elt,
    presentation_limit: NonZero<u32>,
    presentations_used: u32,
}

impl<S: Suite> State<S> {
    /// Randomized generation of a [`Presentation`] from a presentation [`State`].
    ///
    /// Returns [`ArcError::LimitExceeded`] if the state has reached the
    /// maximum number of presentations.
    pub fn present(&mut self, csrng: &mut impl CryptoRngCore) -> Result<Presentation<S>, ArcError> {
        if self.presentations_used >= self.presentation_limit.get() {
            return Err(ArcError::LimitExceeded);
        }

        let presentation = Presentation::new(
            csrng,
            &self.credential,
            &self.presentation_context_tag,
            self.presentation_limit,
            self.presentations_used,
        )?;
        self.presentations_used += 1;
        Ok(presentation)
    }

    /// Returns the number of presentations spent.
    pub fn used_presentations(&self) -> u32 {
        self.presentations_used
    }

    /// Returns the number of presentations still available to use.
    pub fn remaining_presentations(&self) -> u32 {
        self.presentation_limit
            .get()
            .saturating_sub(self.presentations_used)
    }

    /// Serializes to its binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = Credential::<S>::bytes_len()
            + elt_bytes_len::<S>()
            + 2 * ((u32::BITS as usize + 7) >> 3);
        Ser::new(size)
            .add(&self.credential.to_bytes())
            .add(&self.presentation_context_tag)
            .add(&self.presentation_limit.get())
            .add(&self.presentations_used)
            .end()
    }

    /// Recovers from its binary format.
    pub fn from_bytes(b: &[u8]) -> Result<Self, ArcError> {
        let mut d = Des(b);
        let credential = Credential::from_bytes(&d.get_bytes(Credential::<S>::bytes_len())?)?;
        let presentation_context_tag = d.get_element()?;
        let presentation_limit = NonZero::new(d.get()?).ok_or(ArcError::DeserializationFailed)?;
        let presentations_used = d.get()?;

        if presentations_used >= presentation_limit.get() {
            return Err(ArcError::DeserializationFailed);
        }

        let state = Self {
            credential,
            presentation_context_tag,
            presentation_limit,
            presentations_used,
        };

        d.end(state)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct PresentationInner<S: Suite> {
    u: S::Elt,
    u_prime_commit: Commitment<S>,
    m1_commit: Commitment<S>,
    tag: S::Elt,
    nonce_commit: Commitment<S>,
    d: Vec<Commitment<S>>,
}

/// A [`Presentation`] represents an unlinkably show of the Client's [`Credential`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Presentation<S: Suite> {
    inner: PresentationInner<S>,
    proof: Vec<u8>,
    presentation_limit: NonZero<u32>,
}

impl<S: Suite> Presentation<S> {
    /// Tag used for generating zero-knowledge proofs.
    const TAG: &[u8] = b"CredentialPresentation";

    /// Tag used for generating zero-knowledge proofs.
    const TAG_DST: &[u8] = b"Tag";

    /// Randomized generation of a [`Presentation`] from a [`Credential`].
    fn new(
        csrng: &mut impl CryptoRngCore,
        credential: &Credential<S>,
        presentation_context_tag: &S::Elt,
        limit: NonZero<u32>,
        counter: u32,
    ) -> Result<Self, ArcError> {
        let gen_g = S::gen_g();
        let gen_h = S::gen_h()?;

        let [a, r, z] = <S::Elt as ScalarRng>::random_scalars(csrng);
        let u = credential.u * a;
        let u_prime = credential.u_prime * a;
        let u_prime_commit = u_prime + gen_g * r;
        let m1_commit = pedersen_commitment::<S>(&credential.m1, u, &z, gen_h);

        let [nonce_blinding] = <S::Elt as ScalarRng>::random_scalars(csrng);
        let nonce = S::Scalar::from_u128(u128::from(counter));
        let nonce_commit = pedersen_commitment::<S>(&nonce, gen_g, &nonce_blinding, gen_h);

        let gen_t = *presentation_context_tag;
        let inv_m1_nonce = (credential.m1 + nonce)
            .invert()
            .into_option()
            .ok_or(ArcError::ProofFailed)?;
        let tag = gen_t * inv_m1_nonce;
        let v = credential.x1 * z - gen_g * r;
        let range_proof_witness =
            RangeProofWitness::<S>::new(csrng, counter, limit, &nonce_blinding)?;

        // Calculate Pedersen commitments of the bit decomposition (b_i) using randommess (s_i).
        let d = zip(&range_proof_witness.b, &range_proof_witness.s)
            .map(|(bi, si)| pedersen_commitment::<S>(bi, gen_g, si, gen_h))
            .collect();
        let inner = PresentationInner {
            u,
            u_prime_commit,
            m1_commit,
            tag,
            nonce_commit,
            d,
        };
        let witness = [
            [credential.m1, z, -r, nonce, nonce_blinding].as_slice(),
            &range_proof_witness.b,
            &range_proof_witness.s,
            &range_proof_witness.s2,
        ]
        .concat();
        let proof = Self::build_statement(&inner, credential.x1, v, gen_g, gen_h, gen_t)?
            .prove_compact(&witness, csrng)
            .map_err(ArcError::from_sigma)?;

        Ok(Self {
            inner,
            proof,
            presentation_limit: limit,
        })
    }

    /// Builds the statement to be proven or verified by the proof system.
    fn build_statement(
        inner: &PresentationInner<S>,
        x1: S::Elt,
        v: S::Elt,
        g: S::Elt,
        h: S::Elt,
        t: S::Elt,
    ) -> Result<NikzElt<S>, ArcError> {
        let mut statement = LinearRelation::new();
        let [m1, z, r_neg, nonce, nonce_blinding] = statement.allocate_scalars();
        let gen_g = statement.allocate_element_with(g);
        let gen_h = statement.allocate_element_with(h);
        let u = statement.allocate_element_with(inner.u);
        let _: GroupVar<_> = statement.allocate_element_with(inner.u_prime_commit);
        let m1_commit = statement.allocate_element_with(inner.m1_commit);
        let v_var = statement.allocate_element_with(v);
        let x1_var = statement.allocate_element_with(x1);
        let tag = statement.allocate_element_with(inner.tag);
        let gen_t = statement.allocate_element_with(t);
        let nonce_commit = statement.allocate_element_with(inner.nonce_commit);

        statement.append_equation(m1_commit, m1 * u + z * gen_h);
        statement.append_equation(v_var, z * x1_var + r_neg * gen_g);
        statement.append_equation(nonce_commit, nonce * gen_g + nonce_blinding * gen_h);
        statement.append_equation(gen_t, m1 * tag + nonce * tag);

        // Range proof that 0 <= Nonce < Limit.
        let num_bits = inner.d.len();
        let b = statement.allocate_scalars_vec(num_bits);
        let s = statement.allocate_scalars_vec(num_bits);
        let s2 = statement.allocate_scalars_vec(num_bits);

        // Special case: when presentation_limit = 2, D[0] == nonce_commit
        // In this case, reuse nonce_commit_var instead of allocating a new variable
        let d = if num_bits == 1 && inner.d[0] == inner.nonce_commit {
            [nonce_commit].to_vec()
        } else {
            statement.allocate_elements_with(&inner.d)
        };

        for ((bi, si), (s2i, di)) in zip(zip(b, s), zip(s2, d)) {
            statement.append_equation(di, bi * gen_g + si * gen_h);
            statement.append_equation(di, bi * di + s2i * gen_h);
        }

        CanonicalLinearRelation::new_from_lr(statement)
            .into_nizk(&[S::CONTEXT, Self::TAG].concat())
            .map_err(ArcError::from_sigma)
    }

    /// A given [`Presentation`] can be verified using Issuer's [`SecretKey`].
    ///
    /// The function returns `Ok(())` if the presentation is valid and within
    /// the rate limit.
    ///
    /// Note that the presentation is bound to the same request context that
    /// was used for generating a [`Credential`].
    /// The presentation is also bound to the same presentation context and
    /// presentation limit that was used for generating a [`State`].
    ///
    /// # Errors
    ///
    /// Returns [`ArcError::VerificationFailed`] for invalid presentations.
    pub fn verify(
        &self,
        key: &SecretKey<S>,
        request_context: &[u8],
        presentation_limit: NonZero<u32>,
        presentation_context: &[u8],
    ) -> Result<(), ArcError> {
        if presentation_limit != self.presentation_limit
            || self.inner.d.len() != ceil_log2(presentation_limit) as usize
        {
            return Err(ArcError::VerificationFailed);
        }
        // In-memory callers bypass decoding, so enforce the same input rule here.
        let points = [
            self.inner.u,
            self.inner.u_prime_commit,
            self.inner.m1_commit,
            self.inner.tag,
            self.inner.nonce_commit,
        ];
        if points
            .iter()
            .chain(&self.inner.d)
            .any(|point| bool::from(point.is_identity()))
        {
            return Err(ArcError::VerificationFailed);
        }
        let gen_g = S::gen_g();
        let gen_h = S::gen_h()?;
        let m2 = S::hash_to_scalar(request_context, CredentialRequest::<S>::REQUEST_CONTEXT_DST)?;
        let v = self.inner.u * key.mac_key.x0
            + self.inner.m1_commit * key.mac_key.x[0]
            + self.inner.u * (key.mac_key.x[1] * m2)
            - self.inner.u_prime_commit;
        let gen_t = S::hash_to_group(presentation_context, Self::TAG_DST)?;
        if bool::from(gen_t.is_identity()) {
            return Err(ArcError::VerificationFailed);
        }
        let params = key.issuer_params()?;

        // Verify zero-knowledge proof of the presentation.
        let mut result = Presentation::build_statement(
            &self.inner,
            params.mac_params.x[0],
            v,
            gen_g,
            gen_h,
            gen_t,
        )?
        .verify_compact(&self.proof)
        .map_err(ArcError::from_sigma);

        // Verify the sum check: nonceCommit == sum(bases[i] * D[i])
        let bases = compute_bases(presentation_limit);
        if !bases.as_slice().is_empty() {
            let nonce_commit: S::Elt = zip(bases.as_slice(), &self.inner.d)
                .map(|(bi, &di)| di * S::Scalar::from_u128(bi.get() as u128))
                .sum();

            let nonce_commit_bytes = nonce_commit.serialize_into_new_narg();
            let inner_nonce_commit_bytes = self.inner.nonce_commit.serialize_into_new_narg();
            let result_commit = bool::from(
                nonce_commit_bytes
                    .as_ref()
                    .ct_eq(inner_nonce_commit_bytes.as_ref()),
            )
            .then_some(())
            .ok_or(ArcError::VerificationFailed);
            result = result.and(result_commit);
        }

        result
    }

    /// Verify this presentation, then return its canonical protocol tag.
    /// Callers must still enforce application policy and atomic replay claims.
    pub fn verify_and_tag(
        &self,
        key: &SecretKey<S>,
        request_context: &[u8],
        presentation_limit: NonZero<u32>,
        presentation_context: &[u8],
    ) -> Result<Vec<u8>, ArcError> {
        self.verify(
            key,
            request_context,
            presentation_limit,
            presentation_context,
        )?;
        Ok(Ser::new(elt_bytes_len::<S>()).add(&self.inner.tag).end())
    }

    /// Length in bytes of the proof in its serialized format.
    const fn proof_size(presentation_limit: NonZero<u32>) -> usize {
        let k = ceil_log2(presentation_limit) as usize;
        let num_witness = 5 + 3 * k;
        scalar_bytes_len::<S>() * (1 + num_witness)
    }

    /// Length in bytes of its serialized format.
    #[must_use]
    pub fn bytes_len(presentation_limit: NonZero<u32>) -> usize {
        let k = ceil_log2(presentation_limit) as usize;
        (5 + k) * elt_bytes_len::<S>() + Self::proof_size(presentation_limit)
    }

    /// Serializes to its binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        Ser::new(Self::bytes_len(self.presentation_limit))
            .add(&self.inner.u)
            .add(&self.inner.u_prime_commit)
            .add(&self.inner.m1_commit)
            .add(&self.inner.tag)
            .add(&self.inner.nonce_commit)
            .add(&self.inner.d)
            .add(&self.proof)
            .end()
    }

    /// Recovers from its binary format.
    pub fn from_bytes(b: &[u8], presentation_limit: NonZero<u32>) -> Result<Self, ArcError> {
        let k = ceil_log2(presentation_limit);
        let proof_size = Self::proof_size(presentation_limit);
        let mut d = Des::new(b, Self::bytes_len(presentation_limit))?;
        let presentation = Self {
            presentation_limit,
            inner: PresentationInner {
                u: d.get_element()?,
                u_prime_commit: d.get_element()?,
                m1_commit: d.get_element()?,
                tag: d.get_element()?,
                nonce_commit: d.get_element()?,
                d: d.get_element_vec(k as usize)?,
            },
            proof: d.get_bytes(proof_size)?,
        };
        d.end(presentation)
    }

    /// Returns the number of valid presentations.
    pub fn limit(&self) -> NonZero<u32> {
        self.presentation_limit
    }
}

#[cfg(all(test, feature = "suite_p256"))]
#[path = "input_tests.rs"]
mod input_tests;
