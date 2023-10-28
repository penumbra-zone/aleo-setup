//! This module exists to facilitate conversion between data types.
use ark_ec::CurveGroup;
use ark_ff::biginteger::BigInt as ArkBigInt;
use ark_ff::BigInteger384;
//use ark_ff::biginteger::BigInteger as _;
use ark_ff::fields::PrimeField as ArkPrimeField;
//use ark_ff::BigInteger384 as ArkBigInt384;
use ark_serialize::CanonicalSerialize as _;
use phase1::Phase1;
//use setup_utils::{CheckForCorrectness, UseCompression};
use snarkvm_curves::bls12_377::{Bls12_377, Fr};
use snarkvm_curves::{bls12_377::Fq2Parameters, bls12_377::FqParameters, AffineCurve, PairingEngine};
use snarkvm_fields::Fp2;
use snarkvm_utilities::ToBytes;
use std::convert::TryInto;

use crate::penumbra;
use crate::penumbra::single::group as pgroup;

use penumbra_proto::{tools::summoning::v1alpha1::CeremonyCrs, Message};
use rand_core::{CryptoRng, OsRng, RngCore};
use snarkvm_algorithms::msm::variable_base::VariableBaseMSM;
use snarkvm_fields::{Fp384, PrimeField};
//use snarkvm_utilities::biginteger::biginteger::BigInteger384 as SvmBigInt;
use snarkvm_utilities::serialize::CanonicalSerialize;

#[derive(Clone, Debug)]
pub struct TheirStuff {
    tau_powers_g1: Vec<<Bls12_377 as PairingEngine>::G1Affine>,
    tau_powers_g2: Vec<<Bls12_377 as PairingEngine>::G2Affine>,
    alpha_tau_powers_g1: Vec<<Bls12_377 as PairingEngine>::G1Affine>,
    beta_tau_powers_g1: Vec<<Bls12_377 as PairingEngine>::G1Affine>,
    beta_g2: <Bls12_377 as PairingEngine>::G2Affine,
}

impl<'a> From<Phase1<'a, Bls12_377>> for TheirStuff {
    fn from(value: Phase1<'a, Bls12_377>) -> Self {
        Self {
            tau_powers_g1: value.tau_powers_g1,
            tau_powers_g2: value.tau_powers_g2,
            alpha_tau_powers_g1: value.alpha_tau_powers_g1,
            beta_tau_powers_g1: value.beta_tau_powers_g1,
            beta_g2: value.beta_g2,
        }
    }
}

impl<'a, 'b> From<&'b Phase1<'a, Bls12_377>> for TheirStuff {
    fn from(value: &'b Phase1<'a, Bls12_377>) -> Self {
        Self {
            tau_powers_g1: value.tau_powers_g1.clone(),
            tau_powers_g2: value.tau_powers_g2.clone(),
            alpha_tau_powers_g1: value.alpha_tau_powers_g1.clone(),
            beta_tau_powers_g1: value.beta_tau_powers_g1.clone(),
            beta_g2: value.beta_g2.clone(),
        }
    }
}

pub fn convert_phase1_v2<'a>(their_stuff: TheirStuff) -> penumbra_proof_setup::all::Phase1RawCeremonyCRS {
    let [d0, d1, d2, d3, d4, d5, d6] = penumbra::all::circuit_sizes();
    penumbra_proof_setup::all::Phase1RawCeremonyCRS::from_elements([
        convert_phase1_v2_inner(&their_stuff, d0),
        convert_phase1_v2_inner(&their_stuff, d1),
        convert_phase1_v2_inner(&their_stuff, d2),
        convert_phase1_v2_inner(&their_stuff, d3),
        convert_phase1_v2_inner(&their_stuff, d4),
        convert_phase1_v2_inner(&their_stuff, d5),
        convert_phase1_v2_inner(&their_stuff, d6),
    ])
}

fn convert_phase1_v2_inner<'a>(
    their_stuff: &TheirStuff,
    truncate_at_degree: usize,
) -> penumbra_proof_setup::single::Phase1RawCRSElements {
    let d = truncate_at_degree;
    penumbra_proof_setup::single::Phase1RawCRSElements {
        alpha_1: convert_g1(&their_stuff.alpha_tau_powers_g1[0]),
        beta_1: convert_g1(&their_stuff.beta_tau_powers_g1[0]),
        beta_2: convert_g2(&their_stuff.beta_g2),
        x_1: their_stuff
            .tau_powers_g1
            .iter()
            .take(2 * d - 1)
            .map(convert_g1)
            .collect(),
        x_2: their_stuff.tau_powers_g2.iter().take(d).map(convert_g2).collect(),
        alpha_x_1: their_stuff.alpha_tau_powers_g1.iter().take(d).map(convert_g1).collect(),
        beta_x_1: their_stuff.beta_tau_powers_g1.iter().take(d).map(convert_g1).collect(),
    }
}

fn convert_fp(x: SVMFp) -> <penumbra_proof_setup::single::group::G1 as CurveGroup>::BaseField {
    // We assume this returns the actual number associated with the field element.
    let x_repr = x.to_repr();
    // We assume these are u64 limb values, least significant to most significant.
    let x_repr_limbs = x_repr.0;

    let x_repr_new = ArkBigInt::new(x_repr_limbs);
    let x_new = <penumbra_proof_setup::single::group::G1 as CurveGroup>::BaseField::from_bigint(x_repr_new)
        .expect("number should be in range");

    x_new
}

fn convert_fp_ext(x: SVMF2p) -> <penumbra_proof_setup::single::group::G2 as CurveGroup>::BaseField {
    <penumbra_proof_setup::single::group::G2 as CurveGroup>::BaseField::new(convert_fp(x.c0), convert_fp(x.c1))
}

fn convert_g1(p: &<Bls12_377 as PairingEngine>::G1Affine) -> penumbra_proof_setup::single::group::G1 {
    let p = p.mul_by_cofactor();
    assert!(!p.infinity);

    let x_converted = convert_fp(p.x);
    let y_converted = convert_fp(p.y);

    let p_affine =
        <penumbra_proof_setup::single::group::G1 as CurveGroup>::Affine::new_unchecked(x_converted, y_converted);

    p_affine.into()
}

fn convert_g2(p: &<Bls12_377 as PairingEngine>::G2Affine) -> penumbra_proof_setup::single::group::G2 {
    let p = p.mul_by_cofactor();
    assert!(!p.infinity);

    let x_converted = convert_fp_ext(p.x);
    let y_converted = convert_fp_ext(p.y);

    let p_affine =
        <penumbra_proof_setup::single::group::G2 as CurveGroup>::Affine::new_unchecked(x_converted, y_converted);

    p_affine.into()
}

type SVMFp = Fp384<FqParameters>;
type SVMF2p = Fp2<Fq2Parameters>;

fn convert_base_field(x: SVMFp) -> pgroup::FBase {
    let out = <pgroup::FBase as ArkPrimeField>::from_le_bytes_mod_order(&x.to_repr().to_bytes_le().unwrap());
    let in_bytes = {
        let mut data = Vec::new();
        x.serialize(&mut data).unwrap();
        data
    };
    //let out = pgroup::FBase::deserialize_uncompressed(in_bytes.as_slice()).unwrap();
    let out_bytes = {
        let mut data = Vec::new();
        out.serialize_compressed(&mut data).unwrap();
        data
    };
    assert_eq!(in_bytes, out_bytes);
    out
}

fn convert_extension_field(x: SVMF2p) -> pgroup::F2Base {
    pgroup::F2Base {
        c0: convert_base_field(x.c0),
        c1: convert_base_field(x.c1),
    }
}

fn convert(p: &<Bls12_377 as PairingEngine>::G1Affine, _debug: &str) -> pgroup::G1 {
    pgroup::G1Affine {
        x: convert_base_field(p.x),
        y: convert_base_field(p.y),
        infinity: p.infinity,
    }
    .into()
}

fn convert2(p: &<Bls12_377 as PairingEngine>::G2Affine, _debug: &str) -> pgroup::G2 {
    pgroup::G2Affine {
        x: convert_extension_field(p.x),
        y: convert_extension_field(p.y),
        infinity: p.infinity,
    }
    .into()
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

pub fn convert_phase1<'a>(their_stuff: Phase1<'a, Bls12_377>) -> penumbra::all::Phase1CeremonyCRS {
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

pub fn validate<'a>(their_stuff: &TheirStuff) {
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

pub fn write(file: &str, data: penumbra_proof_setup::all::Phase1CeremonyCRS) {
    let proto_encoded_phase_1_root: CeremonyCrs = data.try_into().expect("failed to convert to a protobuf");
    std::fs::write(file, proto_encoded_phase_1_root.encode_to_vec()).expect("failed to write phase1 data");
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    use ark_ec::Group;

    prop_compose! {
        fn arb_scalar()(limbs0 in prop::array::uniform32(any::<u8>()), limbs1 in prop::array::uniform16(any::<u8>())) -> Fr {
            let mut limbs = [0u8; 48];
            limbs[..32].copy_from_slice(&limbs0);
            limbs[32..48].copy_from_slice(&limbs1);
            Fr::from_le_bytes_mod_order(&limbs)
        }
    }

    prop_compose! {
        fn arb_scalar_nonzero()(x in arb_scalar()) -> Fr {
            if x == Fr::from(0u64) {
                return Fr::from(1u64);
            }
            x
        }
    }

    prop_compose! {
        fn arb_their_stuff(d: usize)(tau in arb_scalar_nonzero(), alpha in arb_scalar_nonzero(), beta in arb_scalar_nonzero()) -> TheirStuff {
            let mut tau_i = Fr::from(1u64);

            let mut tau_powers_g1 = Vec::new();
            let mut tau_powers_g2 = Vec::new();
            let mut alpha_tau_powers_g1 = Vec::new();
            let mut beta_tau_powers_g1 = Vec::new();

            for _ in 0..d {
                tau_powers_g1.push(<Bls12_377 as PairingEngine>::G1Affine::prime_subgroup_generator() * tau_i);
                tau_powers_g2.push(<Bls12_377 as PairingEngine>::G2Affine::prime_subgroup_generator() * tau_i);
                alpha_tau_powers_g1.push(<Bls12_377 as PairingEngine>::G1Affine::prime_subgroup_generator() * (alpha * tau_i));
                beta_tau_powers_g1.push(<Bls12_377 as PairingEngine>::G1Affine::prime_subgroup_generator() * (beta * tau_i));
                tau_i *= tau;
            }
            for _ in 0..d - 1 {
                tau_powers_g1.push(<Bls12_377 as PairingEngine>::G1Affine::prime_subgroup_generator() * tau_i);
                tau_i *= tau;
            }
            TheirStuff { tau_powers_g1, tau_powers_g2, alpha_tau_powers_g1, beta_tau_powers_g1, beta_g2: <Bls12_377 as PairingEngine>::G2Affine::prime_subgroup_generator() * beta }
        }
    }

    proptest! {
        #[test]
        fn test_g1_conversion_respects_scalars(mut x in 1u64..) {
            if x == 0 {
                x = 1;
            }
            let their_x_1 = <Bls12_377 as PairingEngine>::G1Affine::prime_subgroup_generator() * Fr::from(x);
            let out_x_1 = penumbra_proof_setup::single::group::G1::generator() * penumbra_proof_setup::single::group::F::from(x);
            assert_eq!(convert_g1(&their_x_1).into_affine(), out_x_1.into_affine());
        }
    }

    proptest! {
        #[test]
        fn test_g2_conversion_respects_scalars(mut x in 1u64..) {
            if x == 0 {
                x = 1;
            }
            let their_x_2 = <Bls12_377 as PairingEngine>::G2Affine::prime_subgroup_generator() * Fr::from(x);
            let out_x_2 = penumbra_proof_setup::single::group::G2::generator() * penumbra_proof_setup::single::group::F::from(x);
            assert_eq!(convert_g2(&their_x_2).into_affine(), out_x_2.into_affine());
        }
    }

    proptest! {
        #[test]
        fn test_phase_conversion_works(their_stuff in arb_their_stuff(4)) {
            validate(&their_stuff);
            let converted = convert_phase1_v2(their_stuff);
            let validated = penumbra_proof_setup::all::Phase1CeremonyCRS::try_from(converted);
            assert!(validated.is_ok());
        }
    }
}
