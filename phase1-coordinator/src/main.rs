use ark_serialize::CanonicalDeserialize;
use snarkvm_curves::{AffineCurve, ProjectiveCurve, PairingEngine, bls12_377::FqParameters};
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
use penumbra::single::group as pgroup;

use phase1_coordinator::penumbra;
use snarkvm_utilities::serialize::CanonicalSerialize;
use snarkvm_fields::{Field, Fp384};

fn coordinator(environment: &Environment, signature: Arc<dyn Signature>) -> anyhow::Result<Coordinator> {
    Ok(Coordinator::new(environment.clone(), signature)?)
}

fn convert(p: &<Bls12_377 as PairingEngine>::G1Affine) -> pgroup::G1 {
    println!("{:?} {:?}", p.x, p.y); 
    let mut x_bytes = Vec::new();
    let mut y_bytes = Vec::new();

    <Fp384<FqParameters> as CanonicalSerialize>::serialize_uncompressed(&p.x, &mut x_bytes).unwrap();
    <Fp384<FqParameters> as CanonicalSerialize>::serialize_uncompressed(&p.y, &mut y_bytes).unwrap();

    let affine_ours = pgroup::G1Affine {
        x: pgroup::FBase::deserialize_uncompressed(&x_bytes[..]).unwrap(),
        y: pgroup::FBase::deserialize_uncompressed(&y_bytes[..]).unwrap(),
        infinity: p.infinity
    };
    todo!()
}

fn thing_we_want0<'a>(their_stuff: &Phase1<'a, Bls12_377>, d: usize) -> penumbra::single::Phase1CRSElements {
    penumbra::single::Phase1CRSElements {
        degree: d,
        raw: penumbra::single::Phase1RawCRSElements {
            alpha_1: convert(&their_stuff.alpha_tau_powers_g1[0]),
            beta_1: todo!(),
            beta_2: todo!(),
            x_1: todo!(),
            x_2: todo!(),
            alpha_x_1: todo!(),
            beta_x_1: todo!(),
        }
    }
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
