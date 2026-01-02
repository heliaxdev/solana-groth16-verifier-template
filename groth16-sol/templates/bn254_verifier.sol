{%- let numPublic = vk.gamma_abc_g1.len() - 1 -%}
// SPDX-License-Identifier: MIT

pragma solidity {{ config.pragma_version }};

/// @title Groth16 verifier template.
/// @author Remco Bloemen and Armada contributors
/// @notice Supports verifying Groth16 proofs.
contract Verifier {

    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_ADD = 0x06;
    uint256 constant PRECOMPILE_MUL = 0x07;
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    // Scalar field Fr order R.
    // For BN254, it is computed as follows:
    //     t = 4965661367192848881
    //     R = 36⋅t⁴ + 36⋅t³ + 18⋅t² + 6⋅t + 1
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X = {{ vk.alpha_g1.x().unwrap() }};
    uint256 constant ALPHA_Y = {{ vk.alpha_g1.y().unwrap() }};

    // Groth16 beta point in G2 in powers of i
    {% let beta_neg = -vk.beta_g2 -%}
    uint256 constant BETA_NEG_X_0 = {{ beta_neg.x().unwrap().c0 }};
    uint256 constant BETA_NEG_X_1 = {{ beta_neg.x().unwrap().c1 }};
    uint256 constant BETA_NEG_Y_0 = {{ beta_neg.y().unwrap().c0 }};
    uint256 constant BETA_NEG_Y_1 = {{ beta_neg.y().unwrap().c1 }};

    // Groth16 gamma point in G2 in powers of i
    {% let gamma_neg = -vk.gamma_g2 -%}
    uint256 constant GAMMA_NEG_X_0 = {{ gamma_neg.x().unwrap().c0 }};
    uint256 constant GAMMA_NEG_X_1 = {{ gamma_neg.x().unwrap().c1 }};
    uint256 constant GAMMA_NEG_Y_0 = {{ gamma_neg.y().unwrap().c0 }};
    uint256 constant GAMMA_NEG_Y_1 = {{ gamma_neg.y().unwrap().c1 }};

    // Groth16 delta point in G2 in powers of i
    {% let delta_neg = -vk.delta_g2 -%}
    uint256 constant DELTA_NEG_X_0 = {{ delta_neg.x().unwrap().c0 }};
    uint256 constant DELTA_NEG_X_1 = {{ delta_neg.x().unwrap().c1 }};
    uint256 constant DELTA_NEG_Y_0 = {{ delta_neg.y().unwrap().c0 }};
    uint256 constant DELTA_NEG_Y_1 = {{ delta_neg.y().unwrap().c1 }};

    // Constant and public input points
    {% let k0 = vk.gamma_abc_g1[0] -%}
    uint256 constant CONSTANT_X = {{ k0.x().unwrap().to_string() }};
    uint256 constant CONSTANT_Y = {{ k0.y().unwrap().to_string() }};
    {%- for ki in vk.gamma_abc_g1 -%}
        {%- if loop.index0 > 0 %}
    uint256 constant PUB_{{loop.index0 - 1}}_X = {{ ki.x().unwrap().to_string() }};
    uint256 constant PUB_{{loop.index0 - 1}}_Y = {{ ki.y().unwrap().to_string() }};
        {%- endif -%}
    {%- endfor %}

    /// Compute the public input linear combination.
    /// @notice Reverts with PublicInputNotInField if the input is not in the field.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    /// @return x The X coordinate of the resulting G1 point.
    /// @return y The Y coordinate of the resulting G1 point.
    function publicInputMSM(uint256[{{ numPublic }}] calldata input)
    internal view returns (uint256 x, uint256 y) {
        // Note: The ECMUL precompile does not reject unreduced values, so we check this.
        // Note: Unrolling this loop does not cost much extra in code-size, the bulk of the
        //       code-size is in the PUB_ constants.
        // ECMUL has input (x, y, scalar) and output (x', y').
        // ECADD has input (x1, y1, x2, y2) and output (x', y').
        // We reduce commitments(if any) with constants as the first point argument to ECADD.
        // We call them such that ecmul output is already in the second point
        // argument to ECADD so we can have a tight loop.
        bool success = true;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let g := add(f, 0x40)
            let s
            mstore(f, CONSTANT_X)
            mstore(add(f, 0x20), CONSTANT_Y)
            {%- for i in (0..numPublic) %}
            mstore(g, PUB_{{ loop.index0 }}_X)
            mstore(add(g, 0x20), PUB_{{ loop.index0 }}_Y)
            {% if loop.index0 == 0 -%}
            s :=  calldataload(input)
            {% elif loop.index0 < numPublic -%}
            s :=  calldataload(add(input, {{ loop.index0 * 0x20}}))
            {% endif -%}
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            {%- endfor %}

            x := mload(f)
            y := mload(add(f, 0x20))
        }
        if (!success) {
            // Either Public input not in field, or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert PublicInputNotInField();
        }
    }

    /// Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        uint256[8] calldata proof,
        uint256[{{ numPublic }}] calldata input
    ) public view {
        (uint256 x, uint256 y) = publicInputMSM(input);

        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40) // Free memory pointer.

            // Copy points (A, B, C) to memory. They are already in correct encoding.
            // This is pairing e(A, B) and G1 of e(C, -δ).
            calldatacopy(f, proof, 0x100)

            // Complete e(C, -δ) and write e(α, -β), e(L_pub, -γ) to memory.
            // OPT: This could be better done using a single codecopy, but
            //      Solidity (unlike standalone Yul) doesn't provide a way to
            //      to do this.
            mstore(add(f, 0x100), DELTA_NEG_X_1)
            mstore(add(f, 0x120), DELTA_NEG_X_0)
            mstore(add(f, 0x140), DELTA_NEG_Y_1)
            mstore(add(f, 0x160), DELTA_NEG_Y_0)
            mstore(add(f, 0x180), ALPHA_X)
            mstore(add(f, 0x1a0), ALPHA_Y)
            mstore(add(f, 0x1c0), BETA_NEG_X_1)
            mstore(add(f, 0x1e0), BETA_NEG_X_0)
            mstore(add(f, 0x200), BETA_NEG_Y_1)
            mstore(add(f, 0x220), BETA_NEG_Y_0)
            mstore(add(f, 0x240), x)
            mstore(add(f, 0x260), y)
            mstore(add(f, 0x280), GAMMA_NEG_X_1)
            mstore(add(f, 0x2a0), GAMMA_NEG_X_0)
            mstore(add(f, 0x2c0), GAMMA_NEG_Y_1)
            mstore(add(f, 0x2e0), GAMMA_NEG_Y_0)

            // Check pairing equation.
            success := staticcall(gas(), PRECOMPILE_VERIFY, f, 0x300, f, 0x20)
            // Also check returned value (both are either 1 or 0).
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
}
