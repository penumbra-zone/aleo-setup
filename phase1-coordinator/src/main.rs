use std::convert::TryInto;
use ark_serialize::CanonicalDeserialize;
use memmap::MmapOptions;
use phase1::{Phase1, Phase1Parameters};
use phase1_coordinator::{
    authentication::{Dummy, Signature},
    environment::{Development, Environment, Parameters},
    Coordinator,
};
use setup_utils::{CheckForCorrectness, UseCompression};
use snarkvm_curves::bls12_377::Bls12_377;
use snarkvm_curves::{bls12_377::FqParameters, AffineCurve, PairingEngine, ProjectiveCurve};
use tracing_subscriber;

use penumbra::single::group as pgroup;
use std::{fs::OpenOptions, sync::Arc, time::Duration};
use tokio::{sync::RwLock, task, time::sleep};
use tracing::*;

use phase1_coordinator::penumbra;
use snarkvm_fields::{Field, Fp384};
use snarkvm_utilities::serialize::CanonicalSerialize;
use penumbra::proto::tools::summoning::v1alpha1::CeremonyCrs;
use penumbra::proto::Message;

fn coordinator(environment: &Environment, signature: Arc<dyn Signature>) -> anyhow::Result<Coordinator> {
    Ok(Coordinator::new(environment.clone(), signature)?)
}

fn convert(p: &<Bls12_377 as PairingEngine>::G1Affine) -> pgroup::G1 {
    let mut x_bytes = Vec::new();
    let mut y_bytes = Vec::new();

    <Fp384<FqParameters> as CanonicalSerialize>::serialize_uncompressed(&p.x, &mut x_bytes).unwrap();
    <Fp384<FqParameters> as CanonicalSerialize>::serialize_uncompressed(&p.y, &mut y_bytes).unwrap();

    let affine_ours = pgroup::G1Affine {
        x: pgroup::FBase::deserialize_uncompressed(&x_bytes[..]).unwrap(),
        y: pgroup::FBase::deserialize_uncompressed(&y_bytes[..]).unwrap(),
        infinity: p.infinity,
    };
    affine_ours.into()
}

fn convert2(p: &<Bls12_377 as PairingEngine>::G2Affine) -> pgroup::G2 {
    let mut bytes = Vec::new();
    p.serialize_uncompressed(&mut bytes);
    pgroup::G2Affine::deserialize_uncompressed(&bytes[..]).unwrap().into()
}

fn thing_we_want0<'a>(their_stuff: &Phase1<'a, Bls12_377>, d: usize) -> penumbra::single::Phase1CRSElements {
    penumbra::single::Phase1CRSElements {
        degree: d,
        raw: penumbra::single::Phase1RawCRSElements {
            alpha_1: convert(&their_stuff.alpha_tau_powers_g1[0]),
            beta_1: convert(&their_stuff.beta_tau_powers_g1[0]),
            beta_2: convert2(&their_stuff.beta_g2),
            x_1: their_stuff.tau_powers_g1[..(2 * d - 1)]
                .iter()
                .map(|x| convert(x))
                .collect(),
            x_2: their_stuff.tau_powers_g2[..d].iter().map(|x| convert2(x)).collect(),
            alpha_x_1: their_stuff.alpha_tau_powers_g1[..d]
                .iter()
                .map(|x| convert(x))
                .collect(),
            beta_x_1: their_stuff.alpha_tau_powers_g1[..d]
                .iter()
                .map(|x| convert(x))
                .collect(),
        },
    }
}

fn thing_we_want<'a>(their_stuff: Phase1<'a, Bls12_377>) -> penumbra::all::Phase1CeremonyCRS {
    let [d0, d1, d2, d3, d4, d5, d6] = penumbra::all::circuit_sizes();
    penumbra::all::Phase1CeremonyCRS([
        thing_we_want0(&their_stuff, d0),
        thing_we_want0(&their_stuff, d1),
        thing_we_want0(&their_stuff, d2),
        thing_we_want0(&their_stuff, d3),
        thing_we_want0(&their_stuff, d4),
        thing_we_want0(&their_stuff, d5),
        thing_we_want0(&their_stuff, d6),
    ])
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
    let phase_1_root = thing_we_want(current_accumulator);
                let proto_encoded_phase_1_root: CeremonyCrs = phase_1_root.try_into()?;
                std::fs::write("phase1.bin", proto_encoded_phase_1_root.encode_to_vec())?;
    Ok(())
}
