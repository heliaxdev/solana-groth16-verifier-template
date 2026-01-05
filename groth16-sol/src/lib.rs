//! # Groth16 Solidity generator
//!
//! A crate for generating Solidity verifier contracts for BN254 Groth16 proofs.
//! This crate uses the `askama` templating engine to render Solidity code based on
//! the provided verifying key and configuration options.
//!
//! The solidity contract is based on the [Groth16 verifier implementation from
//! gnark](https://github.com/Consensys/gnark/blob/9c9cf0deb462ea302af36872669457c36da0f160/backend/groth16/bn254/solidity.go),
//! with minor modifications to be compatible with the [askama](docs.rs/askama) crate.
//!
//! ## Example usage
//! Generation of the Solidity verifier contract can be done as follows and requires the `template` feature to be enabled, which it is by default.
//! If the features is enabled, the crate also re-exports `askama` for convenience.
//! ```rust,no_run
//! # #[cfg(feature = "template")]
//! # {
//! # fn load_verification_key() -> ark_groth16::VerifyingKey<ark_bn254::Bn254> { todo!() }
//! use taceo_groth16_sol::{SolidityVerifierConfig, SolidityVerifierContext};
//! use taceo_groth16_sol::askama::Template;
//! let config = SolidityVerifierConfig::default();
//! let vk : ark_groth16::VerifyingKey<ark_bn254::Bn254> = load_verification_key();
//! let contract = SolidityVerifierContext {
//!     vk,
//!     config,
//! };
//! let rendered = contract.render().unwrap();
//! println!("{}", rendered);
//! // You can also write the rendered contract to a file, see askama documentation for details
//! let mut file = std::fs::File::create("Verifier.sol").unwrap();
//! contract.write_into(&mut file).unwrap();
//! # }
//! ```
//! ## Preparing proofs
//! The crate also provides utility functions to prepare Groth16 proofs for verification in the generated contract.
//! The proofs can be prepared in either compressed or uncompressed format, depending on the specific deployment of the verifier contract.
//! See <https://2π.com/23/bn254-compression> for explanation of the point compression scheme used and explanation of the gas tradeoffs.
//! ```rust,no_run
//! # fn load_proof() -> ark_groth16::Proof<ark_bn254::Bn254> { todo!() }
//! let proof: ark_groth16::Proof<ark_bn254::Bn254> = load_proof();
//! let compressed_proof = taceo_groth16_sol::prepare_compressed_proof(&proof);
//! let uncompressed_proof = taceo_groth16_sol::prepare_uncompressed_proof(&proof);
//! ```
#![deny(missing_docs)]

use std::io::{self, Read};

use alloy_primitives::U256;
use ark_ec::AffineRepr;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;

/// Re-export askama for users of this crate
#[cfg(feature = "template")]
pub use askama;
#[cfg(feature = "template")]
pub use template::{SolidityVerifierConfig, SolidityVerifierContext};

#[cfg(feature = "template")]
pub mod template_filters {
    //! Filters used by the BN254 Groth16 verifier.

    use ark_serialize::CanonicalSerialize;

    #[allow(missing_docs)]
    pub fn le_bytes_g1(
        val: &::ark_bn254::G1Affine,
        _vals: &dyn ::askama::Values,
    ) -> ::askama::Result<String> {
        let mut buf = [0u8; 64];
        val.serialize_uncompressed(&mut buf[..]).unwrap();
        Ok(format!("{buf:?}"))
    }

    #[allow(missing_docs)]
    pub fn be_bytes_g1(
        val: &::ark_bn254::G1Affine,
        _vals: &dyn ::askama::Values,
    ) -> ::askama::Result<String> {
        let mut buf = [0u8; 64];
        val.serialize_uncompressed(&mut buf[..]).unwrap();
        buf[..32].reverse();
        buf[32..].reverse();
        Ok(format!("{buf:?}"))
    }

    #[allow(missing_docs)]
    pub fn le_bytes_g2(
        val: &::ark_bn254::G2Affine,
        _vals: &dyn ::askama::Values,
    ) -> ::askama::Result<String> {
        let mut buf = [0u8; 128];
        val.serialize_uncompressed(&mut buf[..]).unwrap();
        Ok(format!("{buf:?}"))
    }

    #[allow(missing_docs)]
    pub fn be_bytes_g2(
        val: &::ark_bn254::G2Affine,
        _vals: &dyn ::askama::Values,
    ) -> ::askama::Result<String> {
        let mut buf = [0u8; 128];
        val.serialize_uncompressed(&mut buf[..]).unwrap();
        buf[..64].reverse();
        buf[64..].reverse();
        Ok(format!("{buf:?}"))
    }
}

#[cfg(feature = "template")]
mod template {
    use ark_groth16::VerifyingKey;
    use askama::Template;

    use super::template_filters as filters;

    /// Context for generating a Solidity verifier contract for BN254 Groth16 proofs.
    /// The context is passed to `askama` for template rendering.
    /// Parameters:
    /// - `vk`: The [verifying key](ark_groth16::VerifyingKey) for the BN254 curve.
    /// - `config`: Configuration options for the Solidity verifier contract generation.
    #[derive(Debug, Clone, Template)]
    #[template(path = "../templates/bn254_verifier.rs", escape = "none")]
    pub struct SolidityVerifierContext {
        /// asdf
        pub little_endian: bool,
        /// The Groth16 verifying key
        pub vk: VerifyingKey<ark_bn254::Bn254>,
        /// Configuration options for the Solidity verifier contract generation
        pub config: SolidityVerifierConfig,
    }

    /// Configuration for the Solidity verifier contract generation.
    ///
    /// Parameters:
    /// - `pragma_version`: The Solidity pragma version to use in the generated contract. Default is "^0.8.0".
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct SolidityVerifierConfig {
        /// The Solidity pragma version to use in the generated contract. Default is "^0.8.0".
        pub pragma_version: String,
    }

    impl Default for SolidityVerifierConfig {
        fn default() -> Self {
            Self {
                pragma_version: "^0.8.0".to_string(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use askama::Template;
        use circom_types::groth16::VerificationKey;

        const TEST_VK_BN254: &str = include_str!("../data/test_verification_key.json");
        const TEST_GNARK_OUTPUT: &str = include_str!("../data/gnark_output.txt");

        #[test]
        fn test() {
            let config = super::SolidityVerifierConfig::default();
            let vk =
                serde_json::from_str::<VerificationKey<ark_bn254::Bn254>>(TEST_VK_BN254).unwrap();
            let contract = super::SolidityVerifierContext {
                little_endian: false,
                vk: vk.into(),
                config,
            };

            let rendered = contract.render().unwrap();
            // Askama supresses trailing newlines, so we add one for comparison
            let rendered = format!("{}\n", rendered);
            assert_eq!(rendered, TEST_GNARK_OUTPUT);
        }
    }
}

/// Prepare an uncompressed Groth16 proof for verification in the generated contract.
/// The proof is represented as an array of 8 U256 values, corresponding to the
/// x and y coordinates of the points A, B, and C in the proof.
pub fn prepare_uncompressed_proof(proof: &Proof<ark_bn254::Bn254>) -> [U256; 8] {
    // Infinity is represented as (0, 0)
    let (ax, ay) = proof.a.xy().unwrap_or_default();
    // Infinity is represented as (0, 0, 0, 0)
    let (bx, by) = proof.b.xy().unwrap_or_default();
    // Infinity is represented as (0, 0)
    let (cx, cy) = proof.c.xy().unwrap_or_default();

    [
        ax.into(),
        ay.into(),
        bx.c1.into(),
        bx.c0.into(),
        by.c1.into(),
        by.c0.into(),
        cx.into(),
        cy.into(),
    ]
}

/// Read a [verifying key](ark_groth16::VerifyingKey) in Bellman format.
pub fn read_bellman_vk<R: Read>(
    mut reader: R,
) -> Result<ark_groth16::VerifyingKey<ark_bn254::Bn254>, ark_serialize::SerializationError> {
    let read_g1 =
        |reader: &mut R| -> Result<ark_bn254::G1Affine, ark_serialize::SerializationError> {
            <ark_bn254::G1Affine as CanonicalDeserialize>::deserialize_uncompressed(reader)
        };

    let read_g2 =
        |reader: &mut R| -> Result<ark_bn254::G2Affine, ark_serialize::SerializationError> {
            <ark_bn254::G2Affine as CanonicalDeserialize>::deserialize_uncompressed(reader)
        };

    let alpha_g1 = read_g1(&mut reader)?;
    let _beta_g1 = read_g1(&mut reader)?;
    let beta_g2 = read_g2(&mut reader)?;
    let gamma_g2 = read_g2(&mut reader)?;
    let _delta_g1 = read_g1(&mut reader)?;
    let delta_g2 = read_g2(&mut reader)?;

    let ic_len = {
        let mut buf = [0u8; 4];
        reader
            .read_exact(&mut buf)
            .map_err(ark_serialize::SerializationError::IoError)?;
        u32::from_be_bytes(buf)
    };

    let mut ic = vec![];

    for _ in 0..ic_len {
        let g1 = read_g1(&mut reader).and_then(|e| {
            if e == ark_bn254::G1Affine::identity() {
                Err(ark_serialize::SerializationError::IoError(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "point at infinity",
                )))
            } else {
                Ok(e)
            }
        })?;

        ic.push(g1);
    }

    Ok(ark_groth16::VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1: ic,
    })
}
