use ark_ec::Group as _;
use ark_ff::biginteger::BigInt as ArkBigInt;
use ark_ff::biginteger::BigInteger as _;
use ark_ff::fields::PrimeField as ArkPrimeField;
use ark_ff::BigInteger384 as ArkBigInt384;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize as _};
use memmap::MmapOptions;
use phase1::{Phase1, Phase1Parameters};
use phase1_coordinator::{
    authentication::{Dummy, Signature},
    environment::{Development, Environment, Parameters},
    Coordinator,
};
use setup_utils::{CheckForCorrectness, UseCompression};
use snarkvm_curves::bls12_377::Bls12_377;
use snarkvm_curves::{bls12_377::Fq2Parameters, bls12_377::FqParameters, AffineCurve, PairingEngine, ProjectiveCurve};
use snarkvm_fields::Fp2;
use snarkvm_utilities::ToBytes;
use std::convert::TryInto;
use tracing_subscriber;

use penumbra::single::group as pgroup;
use std::{fs::OpenOptions, sync::Arc, time::Duration};
use tokio::{sync::RwLock, task, time::sleep};
use tracing::*;

use penumbra::proto::tools::summoning::v1alpha1::CeremonyCrs;
use penumbra::proto::Message;
use phase1_coordinator::penumbra;
use rand_core::{CryptoRng, OsRng, RngCore};
use snarkvm_algorithms::msm::variable_base::VariableBaseMSM;
use snarkvm_fields::{Field, Fp384, PrimeField};
use snarkvm_utilities::biginteger::biginteger::BigInteger384 as SvmBigInt;
use snarkvm_utilities::{serialize::CanonicalSerialize, ToBits};

use phase1_coordinator::shim;

fn coordinator(environment: &Environment, signature: Arc<dyn Signature>) -> anyhow::Result<Coordinator> {
    Ok(Coordinator::new(environment.clone(), signature)?)
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    tracing::info!("Starting");
    let parameters = Phase1Parameters::<Bls12_377>::new_full(phase1::ProvingSystem::Groth16, 19, 2_097_152);
    // Try to load response file from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open("./round_1057.verified")
        .expect("unable open response file in this directory");
    let response_readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    tracing::info!("Opened file, deserializing into current_accumulator");
    // Deserialize the accumulator
    let current_accumulator = Phase1::deserialize(
        &response_readable_map,
        UseCompression::No, // fails if you pass Yes
        // We've already run with Full
        CheckForCorrectness::No,
        &parameters,
    )
    .expect("unable to read uncompressed accumulator");
    tracing::info!("Finished deserializing");

    tracing::info!("Validating accumulator");
    shim::validate(&current_accumulator);

    tracing::info!("Converting phase1 data (legacy method)");
    //let data = shim::convert_phase1(current_accumulator.clone());

    tracing::info!("Converting phase1 data (new method)");
    let data_v2 = shim::convert_phase1_v2(current_accumulator);
    tracing::info!("Validating phase1 data (new method)");
    let data_v2_validated = penumbra_proof_setup::all::Phase1CeremonyCRS::try_from(data_v2)?;

    tracing::info!("running validate_and_write");
    //shim::validate_and_write("phase1-v5.bin", data);
    Ok(())
}
