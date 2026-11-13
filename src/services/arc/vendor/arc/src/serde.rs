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

// Modified by TokenForge to enforce the draft-01 nonidentity input rule.
use alloc::vec::Vec;
use group::prime::PrimeGroup;

use spongefish::{NargDeserialize, NargSerialize};

use crate::ArcError;

/// Serializer to a binary format.
pub(crate) struct Ser(Vec<u8>);

impl Ser {
    /// Pre-allocates the number of bytes for serialization.
    pub fn new(n: usize) -> Self {
        Self(Vec::with_capacity(n))
    }

    /// Appends the serialization of a struct that implements [`NargSerialize`].
    pub fn add<T: NargSerialize>(mut self, v: &T) -> Self {
        v.serialize_into_narg(&mut self.0);
        self
    }

    /// Returns the vector with the serialized struct consuming `self`.
    pub fn end(self) -> Vec<u8> {
        self.0
    }
}

/// Deserializer from a binary format.
pub(crate) struct Des<'a>(pub &'a [u8]);

impl<'a> Des<'a> {
    /// Checks that the buffer passed for deserialization is of the expected length.
    pub fn new(b: &'a [u8], expected_length: usize) -> Result<Self, ArcError> {
        (b.len() == expected_length)
            .then_some(Self(b))
            .ok_or(ArcError::DeserializationFailed)
    }

    /// Deserialiaze a struct that implements [`NargDeserialize`].
    pub fn get<T: NargDeserialize>(&mut self) -> Result<T, ArcError> {
        T::deserialize_from_narg(&mut self.0).map_err(|_| ArcError::DeserializationFailed)
    }

    /// ARC draft-01 section 6.1 forbids identity elements in P256 input.
    pub fn get_element<T: PrimeGroup + NargDeserialize>(&mut self) -> Result<T, ArcError> {
        let element = self.get::<T>()?;
        if bool::from(element.is_identity()) {
            return Err(ArcError::DeserializationFailed);
        }
        Ok(element)
    }

    pub fn get_element_vec<T: PrimeGroup + NargDeserialize>(
        &mut self,
        n: usize,
    ) -> Result<Vec<T>, ArcError> {
        (0..n).map(|_| self.get_element()).collect()
    }

    /// Returns a vector copying the specified number of bytes.
    pub fn get_bytes(&mut self, n: usize) -> Result<Vec<u8>, ArcError> {
        self.0
            .split_at_checked(n)
            .map(|(head, tail)| {
                self.0 = tail;
                head.to_vec()
            })
            .ok_or(ArcError::DeserializationFailed)
    }

    /// Checks whether the buffer is empty at the end of deserialization.
    pub fn end<T>(self, v: T) -> Result<T, ArcError> {
        self.0
            .is_empty()
            .then_some(v)
            .ok_or(ArcError::DeserializationFailed)
    }
}
