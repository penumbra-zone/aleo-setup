
use memmap::MmapOptions;
use phase1::{Phase1, Phase1Parameters};
use phase1_coordinator::{
    authentication::{Dummy, Signature},
    environment::{Development, Environment, Parameters},
    Coordinator,
};
use setup_utils::{CheckForCorrectness, UseCompression};
use snarkvm_curves::bls12_377::Bls12_377;
use tracing_subscriber;

use std::{fs::OpenOptions, sync::Arc, time::Duration};
use tokio::{sync::RwLock, task, time::sleep};
use tracing::*;

use crate::penumbra;

fn coordinator(environment: &Environment, signature: Arc<dyn Signature>) -> anyhow::Result<Coordinator> {
    Ok(Coordinator::new(environment.clone(), signature)?)
}

fn thing_we_want<'a>(their_stuff: Phase1<'a, Bls12_377>) -> penumbra::all::Phase1CeremonyCRS {
    todo!()
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    println!("HIII");
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

    // Deserialize the accumulator
    let current_accumulator = Phase1::deserialize(
        &response_readable_map,
        UseCompression::No,
        CheckForCorrectness::No,
        &parameters,
    )
    .expect("unable to read uncompressed accumulator");
    Ok(())
}
