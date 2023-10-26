use ark_ec::Group as _;
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
use snarkvm_curves::{bls12_377::FqParameters, AffineCurve, PairingEngine, ProjectiveCurve};
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
use snarkvm_utilities::serialize::CanonicalSerialize;

fn coordinator(environment: &Environment, signature: Arc<dyn Signature>) -> anyhow::Result<Coordinator> {
    Ok(Coordinator::new(environment.clone(), signature)?)
}

fn convert(p: &<Bls12_377 as PairingEngine>::G1Affine, debug: &str) -> pgroup::G1 {
    let mut x_bytes = Vec::new();
    let mut y_bytes = Vec::new();

    p.x.serialize_uncompressed(&mut x_bytes).unwrap();
    p.y.serialize_uncompressed(&mut y_bytes).unwrap();
    let out = pgroup::G1Affine {
        x: pgroup::FBase::deserialize_uncompressed(&x_bytes[..]).unwrap(),
        y: pgroup::FBase::deserialize_uncompressed(&y_bytes[..]).unwrap(),
        infinity: p.infinity,
    };
    let mut bytes = Vec::new();
    p.serialize_uncompressed(&mut bytes).unwrap();
    /*
    let out = pgroup::G1Affine::deserialize_uncompressed(&bytes[..]).unwrap();
    */
    {
        let mut out_x_bytes = Vec::new();
        out.x.serialize_uncompressed(&mut out_x_bytes);
        let mut out_y_bytes = Vec::new();
        out.y.serialize_uncompressed(&mut out_y_bytes);
        let mut out_bytes = Vec::new();
        out.serialize_uncompressed(&mut out_bytes);
        if x_bytes != out_x_bytes {
            panic!("{} (x): left: {:X?}, right: {:X?}", debug, x_bytes, out_x_bytes);
        }
        if y_bytes != out_y_bytes {
            panic!("{} (y): left: {:X?}, right: {:X?}", debug, y_bytes, out_y_bytes);
        }
        /*
        if bytes != out_bytes {
            panic!("{} (x, y): left: {:X?}, right: {:X?}", debug, bytes, out_bytes);
        }
        */
    }
    out.into()
}

fn convert2(p: &<Bls12_377 as PairingEngine>::G2Affine, debug: &str) -> pgroup::G2 {
    let mut x_bytes = Vec::new();
    let mut y_bytes = Vec::new();

    p.x.serialize_uncompressed(&mut x_bytes).unwrap();
    p.y.serialize_uncompressed(&mut y_bytes).unwrap();
    let out = pgroup::G2Affine {
        x: pgroup::F2Base::deserialize_uncompressed(&x_bytes[..]).unwrap(),
        y: pgroup::F2Base::deserialize_uncompressed(&y_bytes[..]).unwrap(),
        infinity: p.infinity,
    };
    let mut bytes = Vec::new();
    p.serialize_uncompressed(&mut bytes).unwrap();
    /*
    let out = pgroup::G1Affine::deserialize_uncompressed(&bytes[..]).unwrap();
    */
    {
        let mut out_x_bytes = Vec::new();
        out.x.serialize_uncompressed(&mut out_x_bytes);
        let mut out_y_bytes = Vec::new();
        out.y.serialize_uncompressed(&mut out_y_bytes);
        let mut out_bytes = Vec::new();
        out.serialize_uncompressed(&mut out_bytes);
        if x_bytes != out_x_bytes {
            panic!("{} (x): left: {:X?}, right: {:X?}", debug, x_bytes, out_x_bytes);
        }
        if y_bytes != out_y_bytes {
            panic!("{} (y): left: {:X?}, right: {:X?}", debug, y_bytes, out_y_bytes);
        }
        /*
        if bytes != out_bytes {
            panic!("{} (x, y): left: {:X?}, right: {:X?}", debug, bytes, out_bytes);
        }
        */
    }
    out.into()
}

fn thing_we_want0<'a>(their_stuff: &Phase1<'a, Bls12_377>, d: usize) -> penumbra::single::Phase1CRSElements {
    let mut x_1 = vec![];
    x_1.extend(
        their_stuff.tau_powers_g1[..(2 * d - 1)]
            .iter()
            .enumerate()
            .map(|(i, x)| convert(x, &format!("x_1_{i}"))),
    );
    let mut x_2 = vec![];
    x_2.extend(
        their_stuff.tau_powers_g2[..d]
            .iter()
            .enumerate()
            .map(|(i, x)| convert2(x, &format!("x_2_{i}"))),
    );
    penumbra::single::Phase1CRSElements {
        degree: d,
        raw: penumbra::single::Phase1RawCRSElements {
            alpha_1: convert(&their_stuff.alpha_tau_powers_g1[0], "alpha1"),
            beta_1: convert(&their_stuff.beta_tau_powers_g1[0], "beta1"),
            beta_2: convert2(&their_stuff.beta_g2, "beta2"),
            x_1,
            x_2,
            alpha_x_1: their_stuff.alpha_tau_powers_g1[..d]
                .iter()
                .enumerate()
                .map(|(i, x)| convert(x, &format!("alpha_x_1_{i}")))
                .collect(),
            beta_x_1: their_stuff.beta_tau_powers_g1[..d]
                .iter()
                .enumerate()
                .map(|(i, x)| convert(x, &format!("beta_x_1_{i}")))
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

fn validate<'a>(their_stuff: &Phase1<'a, Bls12_377>) {
    type F = <Bls12_377 as PairingEngine>::Fr;
    type G1 = <Bls12_377 as PairingEngine>::G1Affine;
    type G2 = <Bls12_377 as PairingEngine>::G2Affine;

    /// Sample a random field that's "small" but still big enough for pairing checks.
    fn rand_small_f<R: CryptoRng + RngCore>(rng: &mut R) -> F {
        // 128 bits of security
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        F::from_le_bytes_mod_order(&bytes)
    }

    pub struct BatchedPairingChecker12 {
        // Invariant: both vecs have the same length.
        vary_l: Vec<G1>,
        base_l: G2,
        vary_r: Vec<G2>,
        base_r: G1,
    }

    impl BatchedPairingChecker12 {
        pub fn new(base_l: impl Into<G2>, base_r: impl Into<G1>) -> Self {
            Self {
                vary_l: Vec::new(),
                base_l: base_l.into(),
                vary_r: Vec::new(),
                base_r: base_r.into(),
            }
        }

        pub fn add(&mut self, l: G1, r: G2) {
            self.vary_l.push(l);
            self.vary_r.push(r);
        }

        #[must_use]
        pub fn check<R: CryptoRng + RngCore>(self, rng: &mut R) -> bool {
            let n = self.vary_l.len();
            let scalars = (0..n).map(|_| rand_small_f(rng).to_repr()).collect::<Vec<_>>();

            let l = VariableBaseMSM::multi_scalar_mul(&self.vary_l, &scalars);
            let r = VariableBaseMSM::multi_scalar_mul(&self.vary_r, &scalars);

            <Bls12_377 as PairingEngine>::pairing(l, self.base_l)
                == <Bls12_377 as PairingEngine>::pairing(self.base_r, r)
        }
    }

    struct BatchedPairingChecker11 {
        // Invariant: both vecs have the same length.
        vary_l: Vec<G1>,
        base_l: G2,
        vary_r: Vec<G1>,
        base_r: G2,
    }

    impl BatchedPairingChecker11 {
        pub fn new(base_l: impl Into<G2>, base_r: impl Into<G2>) -> Self {
            Self {
                vary_l: Vec::new(),
                base_l: base_l.into(),
                vary_r: Vec::new(),
                base_r: base_r.into(),
            }
        }

        pub fn add(&mut self, l: G1, r: G1) {
            self.vary_l.push(l);
            self.vary_r.push(r);
        }

        #[must_use]
        pub fn check<R: CryptoRng + RngCore>(self, rng: &mut R) -> bool {
            let n = self.vary_l.len();
            let scalars = (0..n).map(|_| rand_small_f(rng).to_repr()).collect::<Vec<_>>();

            let l = VariableBaseMSM::multi_scalar_mul(&self.vary_l, &scalars);
            let r = VariableBaseMSM::multi_scalar_mul(&self.vary_r, &scalars);

            <Bls12_377 as PairingEngine>::pairing(l, self.base_l)
                == <Bls12_377 as PairingEngine>::pairing(r, self.base_r)
        }
    }

    // 0. Check that we can extract a valid degree out of these elements.
    println!("(them) checking 0");
    println!("(them) checking 1");
    // 1. Check that the elements committing to the secret values are not 0.
    /*
    if their_stuff.alpha_tau_powers_g1[0].is_zero()
        || their_stuff.beta_tau_powers_g1[0].is_zero()
        || their_stuff.beta_g2.is_zero()
        || their_stuff.tau_powers_g1[1].is_zero()
        || their_stuff.tau_powers_g2[1].is_zero()
    {
        panic!()
    }
        */
    // 2. Check that the two beta commitments match.
    // 3. Check that the x values match on both groups.
    println!("(them) checking 2");
    let mut checker00 = BatchedPairingChecker12::new(G2::prime_subgroup_generator(), G1::prime_subgroup_generator());
    checker00.add(their_stuff.beta_tau_powers_g1[0], their_stuff.beta_g2);
    if !checker00.check(&mut OsRng) {
        panic!("")
    }
    let mut checker01 = BatchedPairingChecker12::new(G2::prime_subgroup_generator(), G1::prime_subgroup_generator());
    println!("(them) checking 3");
    for (&x_1_i, &x_2_i) in their_stuff.tau_powers_g1.iter().zip(their_stuff.tau_powers_g2.iter()) {
        checker01.add(x_1_i, x_2_i);
    }
    if !checker01.check(&mut OsRng) {
        panic!("")
    }

    // 4. Check that alpha and x are connected in alpha_x.
    println!("(them) checking 4");
    let mut checker1 = BatchedPairingChecker12::new(G2::prime_subgroup_generator(), their_stuff.alpha_tau_powers_g1[0]);
    for (&alpha_x_i, &x_i) in their_stuff
        .alpha_tau_powers_g1
        .iter()
        .zip(their_stuff.tau_powers_g2.iter())
    {
        checker1.add(alpha_x_i, x_i);
    }
    if !checker1.check(&mut OsRng) {
        panic!("")
    }
    //
    // 5. Check that beta and x are connected in beta_x.
    println!("(them) checking 5");
    let mut checker2 = BatchedPairingChecker12::new(G2::prime_subgroup_generator(), their_stuff.beta_tau_powers_g1[0]);
    for (&beta_x_i, &x_i) in their_stuff
        .beta_tau_powers_g1
        .iter()
        .zip(their_stuff.tau_powers_g2.iter())
    {
        checker2.add(beta_x_i, x_i);
        break;
    }
    if !checker2.check(&mut OsRng) {
        panic!("")
    }

    // 6. Check that the x_i are the correct powers of x.
    println!("(them) checking 6");
    let mut checker3 = BatchedPairingChecker11::new(their_stuff.tau_powers_g2[1], G2::prime_subgroup_generator());
    for (&x_i, &x_i_plus_1) in their_stuff
        .tau_powers_g1
        .iter()
        .zip(their_stuff.tau_powers_g1.iter().skip(1))
    {
        checker3.add(x_i, x_i_plus_1);
    }
    if !checker3.check(&mut OsRng) {
        panic!("")
    }
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
        // We've already run with Full
        CheckForCorrectness::No,
        &parameters,
    )
    .expect("unable to read uncompressed accumulator");
    validate(&current_accumulator);
    let phase_1_root = thing_we_want(current_accumulator);
    penumbra::all::Phase1RawCeremonyCRS::from(phase_1_root.clone())
        .validate()
        .expect("should be valid");
    let proto_encoded_phase_1_root: CeremonyCrs = phase_1_root.try_into()?;
    std::fs::write("phase1-v4.bin", proto_encoded_phase_1_root.encode_to_vec())?;
    Ok(())
}
