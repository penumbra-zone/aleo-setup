//! This module is very similar to the one for phase1, so reading that one might be useful.
use ark_ec::Group;
use ark_ff::{fields::Field, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand_core::{CryptoRng, RngCore, OsRng};

use crate::penumbra::single::log::{ContributionHash, Hashable, Phase};
use crate::penumbra::single::{
    dlog,
    group::{BatchedPairingChecker11, GroupHasher, F, G1, G2},
};

/// Raw CRS elements, not yet validated for consistency.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct RawCRSElements {
    pub delta_1: G1,
    pub delta_2: G2,
    pub inv_delta_p_1: Vec<G1>,
    pub inv_delta_t_1: Vec<G1>,
}

impl RawCRSElements {
    #[must_use]
    pub fn validate<R: CryptoRng + RngCore>(
        self,
        rng: &mut R,
        root: &CRSElements,
    ) -> Option<CRSElements> {
        // 0. Check that the lengths match that of the root.
        if self.inv_delta_p_1.len() != root.raw.inv_delta_p_1.len()
            || self.inv_delta_t_1.len() != root.raw.inv_delta_t_1.len()
        {
            return None;
        }
        // 1. Check that the elements committing to secret values are not 0.
        if self.delta_1.is_zero() || self.delta_2.is_zero() {
            return None;
        }
        // 2. Check that the two delta commitments match.
        // 3. Check that 1/delta has multiplied the root polynomial p
        // 3. Check that 1/delta has multiplied the root polynomial t
        // We can use one batch check for all of these!
        let mut checker = BatchedPairingChecker11::new(self.delta_2, G2::generator());
        checker.add(G1::generator(), self.delta_1);
        for (&inv_delta_p_i, &p_i) in self.inv_delta_p_1.iter().zip(root.raw.inv_delta_p_1.iter()) {
            checker.add(inv_delta_p_i, p_i);
        }
        for (&inv_delta_t_i, &t_i) in self.inv_delta_t_1.iter().zip(root.raw.inv_delta_t_1.iter()) {
            checker.add(inv_delta_t_i, t_i);
        }
        if !checker.check(rng) {
            return None;
        }

        Some(CRSElements { raw: self })
    }

    /// Convert without checking validity.
    pub(crate) fn assume_valid(self) -> CRSElements {
        CRSElements { raw: self }
    }
}

impl Hashable for RawCRSElements {
    /// Hash these elements, producing a succinct digest.
    fn hash(&self) -> ContributionHash {
        let mut hasher = GroupHasher::new(b"PC$:crs_elmnts2");
        hasher.eat_g1(&self.delta_1);
        hasher.eat_g2(&self.delta_2);

        hasher.eat_usize(self.inv_delta_p_1.len());
        for v in &self.inv_delta_p_1 {
            hasher.eat_g1(v);
        }

        hasher.eat_usize(self.inv_delta_t_1.len());
        for v in &self.inv_delta_t_1 {
            hasher.eat_g1(v);
        }

        ContributionHash(hasher.finalize_bytes())
    }
}

/// The CRS elements we produce in phase 2.
///
/// When combined with the elements of phase 1, the entire CRS will be present.
#[derive(Clone, Debug, PartialEq)]
pub struct CRSElements {
    pub(crate) raw: RawCRSElements,
}

impl Hashable for CRSElements {
    fn hash(&self) -> ContributionHash {
        self.raw.hash()
    }
}

impl CRSElements {
    // TODO: Remove this when no longer needed for testing in summonerd
    pub(crate) fn dummy_root(degree: usize) -> Self {
        Self {
            raw: RawCRSElements {
                delta_1: G1::generator(),
                delta_2: G2::generator(),
                inv_delta_p_1: vec![G1::generator(); degree],
                inv_delta_t_1: vec![G1::generator(); degree],
            },
        }
    }
}

/// Represents a raw, unvalidatedontribution.
#[derive(Clone, Debug)]
pub struct RawContribution {
    pub parent: ContributionHash,
    pub new_elements: RawCRSElements,
    pub(crate) linking_proof: dlog::Proof,
}

impl RawContribution {
    /// Check the internal integrity of this contribution, potentially producing
    /// a valid one.
    pub fn validate<R: CryptoRng + RngCore>(
        self,
        rng: &mut R,
        root: &CRSElements,
    ) -> Option<Contribution> {
        self.new_elements
            .validate(rng, root)
            .map(|new_elements| Contribution {
                parent: self.parent,
                new_elements,
                linking_proof: self.linking_proof,
            })
    }

    /// Skip validation, and perform a conversion anyways.
    ///
    /// Can be useful when parsing data that's known to be good.
    pub(crate) fn assume_valid(self) -> Contribution {
        Contribution {
            parent: self.parent,
            new_elements: self.new_elements.assume_valid(),
            linking_proof: self.linking_proof,
        }
    }
}

impl Hashable for RawContribution {
    fn hash(&self) -> ContributionHash {
        let mut hasher = GroupHasher::new(b"PC$:contrbution2");
        hasher.eat_bytes(self.parent.as_ref());
        hasher.eat_bytes(self.new_elements.hash().as_ref());
        hasher.eat_bytes(self.linking_proof.hash().as_ref());

        ContributionHash(hasher.finalize_bytes())
    }
}

impl From<Contribution> for RawContribution {
    fn from(value: Contribution) -> Self {
        Self {
            parent: value.parent,
            new_elements: value.new_elements.raw,
            linking_proof: value.linking_proof,
        }
    }
}

/// Represents a contribution to phase2 of the ceremony.
///
/// This contribution is linked to the previous contribution it builds upon.
///
/// The contribution contains new CRS elements, and a proof linking these elements
/// to those of the parent contribution.
#[derive(Clone, Debug)]
pub struct Contribution {
    pub parent: ContributionHash,
    pub new_elements: CRSElements,
    pub(crate) linking_proof: dlog::Proof,
}

impl Hashable for Contribution {
    fn hash(&self) -> ContributionHash {
        RawContribution::from(self.to_owned()).hash()
    }
}

impl Contribution {
    /// Make a new contribution, over the previous CRS elements.
    ///
    /// We also need a hash of the parent contribution we're building on.
    pub fn make<R: CryptoRng + RngCore>(
        rng: &mut R,
        parent: ContributionHash,
        old: &CRSElements,
    ) -> Self {
        let delta = F::rand(rng);
        // e.w. negligible probability this will panic (1 / 2^256)
        let delta_inv = delta.inverse().expect("unable to inverse delta");

        let mut new = old.clone();
        new.raw.delta_1 *= delta;
        new.raw.delta_2 *= delta;
        for v in &mut new.raw.inv_delta_p_1 {
            *v *= delta_inv;
        }
        for v in &mut new.raw.inv_delta_t_1 {
            *v *= delta_inv;
        }

        let linking_proof = dlog::prove(
            rng,
            b"phase2 delta proof",
            dlog::Statement {
                result: new.raw.delta_1,
                base: old.raw.delta_1,
            },
            dlog::Witness { dlog: delta },
        );

        Contribution {
            parent,
            new_elements: new,
            linking_proof,
        }
    }

    /// Verify that this contribution is linked to a previous list of elements.
    #[must_use]
    pub fn is_linked_to(&self, parent: &CRSElements) -> bool {
        // 1. Check that the sizes match between the two elements.
        if self.new_elements.raw.inv_delta_p_1.len() != parent.raw.inv_delta_p_1.len()
            || self.new_elements.raw.inv_delta_t_1.len() != parent.raw.inv_delta_t_1.len()
        {
            return false;
        }
        // 2. Check that the linking proof verifies
        if !dlog::verify(
            b"phase2 delta proof",
            dlog::Statement {
                result: self.new_elements.raw.delta_1,
                base: parent.raw.delta_1,
            },
            &self.linking_proof,
        ) {
            return false;
        }
        true
    }
}

/// A dummy struct to implement the phase trait.
#[derive(Clone, Debug, Default)]
struct Phase2;

impl Phase for Phase2 {
    type CRSElements = CRSElements;

    type RawContribution = RawContribution;

    type Contribution = Contribution;

    fn parent_hash(contribution: &Self::RawContribution) -> ContributionHash {
        contribution.parent
    }

    fn elements(contribution: &Self::Contribution) -> &Self::CRSElements {
        &contribution.new_elements
    }

    fn validate(
        root: &Self::CRSElements,
        contribution: &Self::RawContribution,
    ) -> Option<Self::Contribution> {
        contribution.to_owned().validate(&mut OsRng, root)
    }

    fn is_linked_to(contribution: &Self::Contribution, elements: &Self::CRSElements) -> bool {
        contribution.is_linked_to(elements)
    }
}

