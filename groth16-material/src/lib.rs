//! Groth16 zk-SNARK proof generation and verification.
//!
//! This crate provides functionality for working with R1CS witnesses and Groth16 proofs.
//!
//! Currently, it supports circuits defined using Circom.
#![deny(missing_docs)]

#[cfg(feature = "circom")]
pub mod circom;

/// Errors that can occur during Groth16 proof generation and verification.
#[derive(Debug, thiserror::Error)]
pub enum Groth16Error {
    /// Failed to generate a witness for the circuit.
    #[error("failed to generate witness")]
    WitnessGeneration(#[source] eyre::Report),
    /// Failed to generate a Groth16 proof.
    #[error("failed to generate proof")]
    ProofGeneration(#[source] eyre::Report),
    /// Generated proof could not be verified against the verification key.
    #[error("proof could not be verified")]
    InvalidProof,
}
