//! Macros for use with this crate.

/// Returns the total number of powers of tau G1 given a proving system and the number of powers.
#[macro_export]
macro_rules! total_size_in_g1 {
    ($proving_system:ident, $power:ident) => {{
        use $crate::ProvingSystem;

        match $proving_system {
            ProvingSystem::Groth16 => ((1 << ($power + 1)) - 1),
            ProvingSystem::Marlin => (1 << $power),
        }
    }};
}

/// Returns the chunk size given the desired number of chunks, the proving system,
/// and the number of powers.
#[macro_export]
macro_rules! chunk_size {
    ($num_chunks:ident, $proving_system:ident, $power:ident) => {{
        (($crate::total_size_in_g1!($proving_system, $power) + $num_chunks - 1) / $num_chunks)
    }};
}
