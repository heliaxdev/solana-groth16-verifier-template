{%- let num_public_inputs = vk.gamma_abc_g1.len() -%}

use alloc::alloc::{alloc as allocate, dealloc, Layout};
use core::mem;

const NUM_PUBLIC_INPUTS: usize = {{ num_public_inputs }};

const BUFFER_SIZE: usize = {
    64 /* output register */ + 768 /* pairing input */
};
const BUFFER_MEM_LAYOUT: Layout = unsafe {
    Layout::from_size_align_unchecked(
        BUFFER_SIZE,
        mem::align_of::<[u8; BUFFER_SIZE]>(),
    )
};

mod bn254 {
    // Reference: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0129-alt-bn128-simplified-error-code.md

    use solana_define_syscall::definitions as syscalls;

    const G1_ADD_BE: u64 = 0;
    const G1_SCALAR_MUL_BE: u64 = 2;
    const PAIRING_CHECK_BE: u64 = 3;

    {%- if little_endian %}
    const LE_FLAG: u64 = 0x80;
    const G1_ADD_LE: u64 = G1_ADD_BE | LE_FLAG;
    const G1_SCALAR_MUL_LE: u64 = G1_SCALAR_MUL_BE | LE_FLAG;
    const PAIRING_CHECK_LE: u64 = PAIRING_CHECK_BE | LE_FLAG;
    {%- endif %}

    #[inline(never)]
    #[cold]
    unsafe fn abort() -> ! {
        unsafe { syscalls::abort() }
    }

    #[inline(always)]
    pub unsafe fn g1_add(
        output: *mut u8, // 64 bytes
        input: *const u8, // 128 bytes
    ) {
        let result = unsafe {
            syscalls::sol_alt_bn128_group_op(
                {%- if little_endian %}
                G1_ADD_LE,
                {%- else %}
                G1_ADD_BE,
                {%- endif %}
                input,
                128,
                output,
            )
        };

        if result != 0 {
            unsafe { abort() }
        }
    }

    #[inline(always)]
    pub unsafe fn g1_scalar_mul(
        output: *mut u8, // 64 bytes
        input: *const u8, // 96 bytes
    ) {
        let result = unsafe {
            syscalls::sol_alt_bn128_group_op(
                {%- if little_endian %}
                G1_SCALAR_MUL_LE,
                {%- else %}
                G1_SCALAR_MUL_BE,
                {%- endif %}
                input,
                96,
                output,
            )
        };

        if result != 0 {
            unsafe { abort() }
        }
    }

    #[inline(always)]
    pub unsafe fn pairing_check(
        output: *mut u8, // 32 bytes
        input: *const u8, // 192*4 = 768 bytes
    ) {
        let result = unsafe {
            syscalls::sol_alt_bn128_group_op(
                {%- if little_endian %}
                PAIRING_CHECK_LE,
                {%- else %}
                PAIRING_CHECK_BE,
                {%- endif %}
                input,
                576,
                output,
            )
        };

        {%- if little_endian %}
        let pairing_check_result_off = output;
        {%- else %}
        let pairing_check_result_off = unsafe { output.add(31) };
        {%- endif %}

        if result != 0 || unsafe { *pairing_check_result_off } != 1 {
            unsafe { abort() }
        }
    }
}

mod groth16 {
    use super::bn254;

    // Groth16 pairing check template
    const PAIRING_CHECK_TEMPLATE: [u8; 768] = {
        let mut i;
        let mut out = [0u8; 768];

        // Groth16 alpha point in G1
        {%- if little_endian %}
        const ALPHA: [u8; 64] = {{ &vk.alpha_g1|le_bytes_g1 }};
        {%- else %}
        const ALPHA: [u8; 64] = {{ &vk.alpha_g1|be_bytes_g1 }};
        {%- endif %}

        // Groth16 beta point in G2
        {% let beta_neg = -vk.beta_g2 -%}
        {%- if little_endian %}
        const BETA_NEG: [u8; 128] = {{ &beta_neg|le_bytes_g2 }};
        {%- else %}
        const BETA_NEG: [u8; 128] = {{ &beta_neg|be_bytes_g2 }};
        {%- endif %}

        // Groth16 gamma point in G2
        {% let gamma_neg = -vk.gamma_g2 -%}
        {%- if little_endian %}
        const GAMMA_NEG: [u8; 128] = {{ &gamma_neg|le_bytes_g2 }};
        {%- else %}
        const GAMMA_NEG: [u8; 128] = {{ &gamma_neg|be_bytes_g2 }};
        {%- endif %}

        // Groth16 delta point in G2
        {% let delta_neg = -vk.delta_g2 -%}
        {%- if little_endian %}
        const DELTA_NEG: [u8; 128] = {{ &delta_neg|le_bytes_g2 }};
        {%- else %}
        const DELTA_NEG: [u8; 128] = {{ &delta_neg|be_bytes_g2 }};
        {%- endif %}

        // e(A, B) x e(C, -δ) x e(α, -β) x e(L_pub, -γ) = 1
        // 0..191   192..383    384..575   576..767
        i = 0;
        while i < 128 {
            out[0x100 + i] = DELTA_NEG[i];
            i += 1;
        }
        i = 0;
        while i < 64 {
            out[0x180 + i] = ALPHA[i];
            i += 1;
        }
        i = 0;
        while i < 128 {
            out[0x1c0 + i] = BETA_NEG[i];
            i += 1;
        }
        i = 0;
        while i < 128 {
            out[0x280 + i] = GAMMA_NEG[i];
            i += 1;
        }

        out
    };

    // Public input points
    {%- for p in vk.gamma_abc_g1 %}
    {%- if little_endian %}
    static IC_{{ loop.index0 }}: [u8; 64] = {{ p|le_bytes_g1 }};
    {%- else %}
    static IC_{{ loop.index0 }}: [u8; 64] = {{ p|be_bytes_g1 }};
    {%- endif %}
    {%- endfor %}

    {%- if num_public_inputs > 0 %}
    #[inline(always)]
    unsafe fn msm(
        output: *mut u8, // 64 bytes
        input: *const u8, // 32 * NUM_PUBLIC_INPUTS = {{ 32 * num_public_inputs }} bytes
        scratch: *mut u8, // scratch buffer (128 bytes)
    ) {
        unsafe {
            syscalls::sol_memcpy_(
                scratch,
                &IC_0 as *const _ as *const _,
                64,
            );
            syscalls::sol_memcpy_(
                scratch.add(64),
                input,
                32,
            );
            g1_scalar_mul(
                output,
                scratch,
            );
        }

        {%- for i in (1..num_public_inputs) %}
        unsafe {
            syscalls::sol_memcpy_(
                scratch,
                &IC_{{ i }} as *const _ as *const _,
                64,
            );
            syscalls::sol_memcpy_(
                scratch.add(64),
                input,
                32,
            );
            g1_scalar_mul(
                scratch,
                scratch,
            );

            syscalls::sol_memcpy_(
                scratch.add(64),
                output,
                64,
            );
            g1_add(
                output,
                scratch,
            )
        }
        {%- endfor %}
    }
    {%- endif %}

    fn verify(
        // [
        //   0..31    -- public input 1
        //   31..63   -- public input 2
        //   ..n*32-1 -- public input n
        //   n*32..   -- proof data
        // ]
        pub_witness_and_proof: &[u8],
    ) {
        const PROOF_LEN: usize = 256;
        const WITNESS_LEN: usize = 32 * NUM_PUBLIC_INPUTS;

        if pub_witness_and_proof.len() < const { PROOF_LEN + WITNESS_LEN } {
            unsafe { abort() }
        }

        let buf = unsafe { allocate(BUFFER_MEM_LAYOUT) };

        {%- if num_public_inputs > 0 %}
        unsafe { msm(buf, pub_witness_and_proof.as_ptr(), buf.add(64)); }
        {%- endif %}

        unsafe {
            syscalls::sol_memcpy_(
                buf.add(64),
                &PAIRING_CHECK_TEMPLATE as *const _ as *const _,
                768,
            );

            // e(A, B) x e(C, -δ) x e(α, -β) x e(L_pub, -γ) = 1
            // 0..191   192..383    384..575   576..767

            // copy proof
            syscalls::sol_memcpy_(
                buf.add(64),
                pub_witness_and_proof.as_ptr().add(WITNESS_LEN),
                256,
            );
            // copy msm result
            syscalls::sol_memcpy_(
                buf.add(const { 64 + 576 }),
                buf,
                64,
            );
        }
        unsafe { pairing_check(buf, buf.add(64) ) }

        unsafe { dealloc(buf, BUFFER_MEM_LAYOUT); }
    }
}
